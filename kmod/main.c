/*
 *  Copyright (C) 2017 jianhui zhao <jianhuizhao329@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <net/arp.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>

#include <linux/slab.h>
#include <linux/string.h>

#include "config.h"
#include "term_manage.h"
#include "ip_manage.h"

//#define WIFIDOG_DEBUG

#ifdef WIFIDOG_DEBUG
#define w_debug(fmt, arg...) printk("[%s][%d]"fmt, __FILE__, __LINE__, ##arg)
#else
#define w_debug(fmt, arg...)
#endif

#define IPS_HIJACKED    (1 << 31)
#define IPS_ALLOWED     (1 << 30)

static u32 __nf_nat_setup_info(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct nf_conn *ct)
{
    struct config *conf = get_config();
    struct tcphdr *tph = tcp_hdr(skb);
    union nf_conntrack_man_proto proto;
    struct nf_nat_range newrange;
    static uint16_t PORT_80 = htons(80);

    proto.tcp.port = (tph->dest == PORT_80) ? htons(conf->port) : htons(conf->ssl_port);
    newrange.flags       = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
    newrange.min_addr.ip = newrange.max_addr.ip = conf->interface_ipaddr;
    newrange.min_proto   = newrange.max_proto = proto;

    ct->status |= IPS_HIJACKED;

    return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_DST);
}

static u32 wifidog_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct config *conf = get_config();
    struct ethhdr *ehdr = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    struct nf_conn *ct;
    struct tcphdr *tph;
    struct udphdr *uph;
    struct terminal *term = NULL;
    enum ip_conntrack_info ctinfo;
    static uint16_t PORT_22 = htons(22);    /* ssh */
    static uint16_t PORT_80 = htons(80);    /* http */
    static uint16_t PORT_443 = htons(443);  /* https */
    static uint16_t PORT_53 = htons(53);    /* dns */
    static uint16_t PORT_123 = htons(123);  /* ntp */

    if (unlikely(!conf->enabled))
        return NF_ACCEPT;

    if (unlikely(state->in->ifindex != conf->interface_ifindex))
        return NF_ACCEPT;

    /* Accept all from non local area networks */
    if ((iph->saddr | ~conf->interface_mask) != conf->interface_broadcast)
        return NF_ACCEPT;

    /* Accept broadcast */
    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST)
        return NF_ACCEPT;

    /* Accept to us */
    if (iph->daddr == conf->interface_ipaddr)
        return NF_ACCEPT;

    ct = nf_ct_get(skb, &ctinfo);
    if (!ct)
        return NF_ACCEPT;

    term = find_term_by_mac_lock(ehdr->h_source, true);
    if (likely(term)) {
        update_term(term, iph->saddr);
    } else {
        return NF_DROP;
    }

    if ((ct->status & IPS_HIJACKED) || (ct->status & IPS_ALLOWED)) {
        if ((ct->status & IPS_HIJACKED) && term_is_allowed(ehdr->h_source)) {
            /* Avoid duplication of authentication */
            nf_reset(skb);
            nf_ct_kill(ct);
        }
        return NF_ACCEPT;
    } else if (ctinfo == IP_CT_NEW && (allowed_dest_ip(iph->daddr) || term_is_allowed(ehdr->h_source))) {
        ct->status |= IPS_ALLOWED;
        return NF_ACCEPT;
    }

    switch (iph->protocol) {
    case IPPROTO_TCP:
        tph = tcp_hdr(skb);
        if(PORT_22 == tph->dest) {
            ct->status |= IPS_ALLOWED;
            return NF_ACCEPT;
        } else if ((PORT_443 != tph->dest) && (PORT_80 != tph->dest)) {
            return NF_DROP;
        }
        break;

    case IPPROTO_UDP:
        uph = udp_hdr(skb);
        if(uph->dest == PORT_53 || uph->dest == PORT_123) {
            ct->status |= IPS_ALLOWED;
            return NF_ACCEPT;
        }
        return NF_DROP;
        break;

    default:
        ct->status |= IPS_ALLOWED;
        return NF_ACCEPT;
    }

    /* all packets from unknown client are dropped */
    if (ctinfo != IP_CT_NEW || (ct->status & IPS_DST_NAT_DONE)) {
        w_debug("dropping packets of suspect stream, src:%pI4, dst:%pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }

    return nf_nat_ipv4_in(priv, skb, state, __nf_nat_setup_info);
}

static u32 term_statistic_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct config *conf = get_config();
    struct ethhdr *ehdr = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    struct terminal *term = NULL;
    __be32 saddr, daddr;
    u8 from_lan = 0;
    u8  to_lan = 0;

    if (ipv4_is_lbcast(iph->daddr) || ipv4_is_multicast(iph->saddr)
        || ipv4_is_multicast(iph->daddr)) {
            return NF_ACCEPT;
    }

    saddr = iph->saddr;
    daddr = iph->daddr;

    if ((saddr | ~conf->interface_mask) == conf->interface_broadcast)
        from_lan = 1;

    if ((daddr | ~conf->interface_mask) == conf->interface_broadcast)
        to_lan = 1;

    /* skip lan <-> lan & wan <-> wan */
    if (unlikely(from_lan == to_lan))
        return NF_ACCEPT;

    if (from_lan) {
        term = find_term_by_mac(ehdr->h_source, false);
        if (unlikely(!term))
            return NF_ACCEPT;
    } else if (to_lan) {
        struct neighbour *n = __ipv4_neigh_lookup_noref(state->out, daddr);
        if (n) {
            term = find_term_by_mac(n->ha, false);
            if (unlikely(!term))
                return NF_ACCEPT;
        }
    }

    /* Upload */
    if (from_lan)
        term->flow.tx += skb->len;

    /* Download */
    if (to_lan)
        term->flow.rx += skb->len;

    return NF_ACCEPT;
}

static struct nf_hook_ops wifidog_ops[] __read_mostly = {
    {
        .hook       = wifidog_hook,
        .pf         = PF_INET,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority   = NF_IP_PRI_CONNTRACK + 1 /* after conntrack */
    },
    {
        .hook       = term_statistic_hook,
        .pf         = PF_INET,
        .hooknum    = NF_INET_FORWARD,
        .priority   = NF_IP_PRI_LAST
    },
};

static int __init wifidog_init(void)
{
    int ret;
    struct proc_dir_entry *proc;

    ret = init_config();
    if (ret)
        return ret;

    proc = get_proc_dir_entry();

    ret = term_init(proc);
    if (ret) {
        pr_err("term_init failed\n");
        goto remove_config;
    }

    ret = ip_manage_init(proc);
    if (ret) {
        pr_err("ip_manage_init failed\n");
        goto free_term;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 14)
    ret = nf_register_net_hooks(&init_net, wifidog_ops, ARRAY_SIZE(wifidog_ops));
#else
    ret = nf_register_hooks(wifidog_ops, ARRAY_SIZE(wifidog_ops));
#endif
    if (ret < 0) {
        pr_err("can't register hook\n");
        goto free_tip;
    }

    pr_info("kmod of wifidog is started\n");

    return 0;

free_tip:
    ip_manage_free(proc);
free_term:
    term_free(proc);
remove_config:
    deinit_config();
    return ret;
}

static void __exit wifidog_exit(void)
{
    struct proc_dir_entry *proc = get_proc_dir_entry();

    term_free(proc);
    ip_manage_free(proc);
    deinit_config();

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 14)
    nf_unregister_net_hooks(&init_net, wifidog_ops, ARRAY_SIZE(wifidog_ops));
#else
    nf_unregister_hooks(wifidog_ops, ARRAY_SIZE(wifidog_ops));
#endif

    pr_info("kmod of wifidog is stop\n");
}

module_init(wifidog_init);
module_exit(wifidog_exit);

MODULE_AUTHOR("jianhui zhao <jianhuizhao329@gmail.com>");
MODULE_LICENSE("GPL");

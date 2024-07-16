/*
 *  Copyright (C) 2017 jianhui zhao <zhaojh329@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/netfilter/ipset/ip_set.h>
#include <net/netfilter/nf_nat.h>
#include <net/netns/generic.h>
#include <linux/inetdevice.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#include <net/netfilter/nf_nat_l3proto.h>
#endif


#define PROC_DIR_NAME "wifidog-ng"

#define IPS_HIJACKED    (1 << 31)
#define IPS_ALLOWED     (1 << 30)

static unsigned int wd_net_id __read_mostly;

struct wifidog_net {
	struct net *net;
	struct proc_dir_entry *proc_dir;

    int enabled;
    char interface[IFNAMSIZ];
    int interface_ifindex;
    __be32 interface_ipaddr;
    __be32 interface_mask;
    __be32 interface_broadcast;
    __be16 port;
    __be16 ssl_port;
};

static int update_gw_interface(struct wifidog_net *wd)
{
    struct in_device *in_dev;
    struct net_device *dev;
    int ret = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 2, 0)
    const struct in_ifaddr *ifa;
#endif

    dev = dev_get_by_name(wd->net, wd->interface);
    if (!dev) {
        pr_err("wifidog-ng: Not found interface: %s\n", wd->interface);
        return -ENOENT;
    }

    wd->interface_ifindex = dev->ifindex;

    in_dev = inetdev_by_index(wd->net, wd->interface_ifindex);
    if (!in_dev) {
        pr_err("wifidog-ng: Not found in_dev on %s\n", wd->interface);
        ret = -ENOENT;
        goto QUIT;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    for_primary_ifa(in_dev) {
#else
    in_dev_for_each_ifa_rcu(ifa, in_dev) {
#endif
        wd->interface_ipaddr = ifa->ifa_local;
        wd->interface_mask = ifa->ifa_mask;
        wd->interface_broadcast = ifa->ifa_broadcast;

        pr_info("wifidog-ng: Found ip from %s: %pI4\n", wd->interface, &wd->interface_ipaddr);
        break;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    endfor_ifa(in_dev);
#endif

QUIT:   
    dev_put(dev);

    return ret;
}

static int proc_config_show(struct seq_file *s, void *v)
{
    struct wifidog_net *wd = net_generic(current->nsproxy->net_ns, wd_net_id);

    seq_printf(s, "enabled(RW) = %d\n", wd->enabled);
    seq_printf(s, "interface(RW) = %s\n", wd->interface);
    seq_printf(s, "ipaddr(RO) = %pI4\n", &wd->interface_ipaddr);
    seq_printf(s, "netmask(RO) = %pI4\n", &wd->interface_mask);
    seq_printf(s, "broadcast(RO) = %pI4\n", &wd->interface_broadcast);
    seq_printf(s, "port(RW) = %d\n", ntohs(wd->port));
    seq_printf(s, "ssl_port(RW) = %d\n", ntohs(wd->ssl_port));

    return 0;
}

static ssize_t proc_config_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
    struct wifidog_net *wd = net_generic(current->nsproxy->net_ns, wd_net_id);
    char data[128];
    char *delim, *key;
    const char *value;
    int update = 0;

    if (size == 0)
        return -EINVAL;

    if (size > sizeof(data))
        size = sizeof(data);

    if (copy_from_user(data, buf, size))
        return -EFAULT;

    data[size - 1] = 0;

    key = data;
    while (key && *key) {
        while (*key && (*key == ' '))
            key++;

        delim = strchr(key, '=');
        if (!delim)
            break;

        *delim++ = 0;
        value = delim;

        delim = strchr(value, '\n');
        if (delim)
            *delim++ = 0;

        if (!strcmp(key, "enabled")) {
            wd->enabled = simple_strtol(value, NULL, 0);
            if (wd->enabled)
                update = 1;
            pr_info("wifidog-ng: %s\n", wd->enabled ? "enabled" : "disabled");
        } else if (!strcmp(key, "interface")) {
            strncpy(wd->interface, value, sizeof(wd->interface) - 1);
            update = 1;
        } else if (!strcmp(key, "port")) {
            wd->port = htons(simple_strtol(value, NULL, 0));
        } else if (!strcmp(key, "ssl_port")) {
            wd->ssl_port = htons(simple_strtol(value, NULL, 0));
        }

        key = delim;
    }

    if (update)
        update_gw_interface(wd);

    return size;
}

static int proc_config_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_config_show, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
const static struct file_operations proc_config_ops = {
    .owner      = THIS_MODULE,
    .open       = proc_config_open,
    .read       = seq_read,
    .write      = proc_config_write,
    .llseek     = seq_lseek,
    .release    = single_release
};
#else
const static struct proc_ops proc_config_ops = {
    .proc_open       = proc_config_open,
    .proc_read       = seq_read,
    .proc_write      = proc_config_write,
    .proc_lseek     = seq_lseek,
    .proc_release    = single_release
};
#endif


static inline int wd_ip_set_test(const char *name, const struct sk_buff *skb,
    struct ip_set_adt_opt *opt, const struct nf_hook_state *state)
{
    static struct xt_action_param par = { };
    struct ip_set *set = NULL;
    ip_set_id_t index;
    int ret;

    index = ip_set_get_byname(state->net, name, &set);
    if (!set)
        return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
    par.net = state->net;
#else
    par.state = state;
#endif

    ret = ip_set_test(index, skb, &par, opt);
    ip_set_put_byindex(state->net, index);
    return ret;
}

static inline int is_allowed_mac(struct sk_buff *skb, const struct nf_hook_state *state)
{
    static struct ip_set_adt_opt opt = {
        .family = NFPROTO_IPV4,
        .dim = IPSET_DIM_ONE,
        .flags = IPSET_DIM_ONE_SRC,
        .ext.timeout = UINT_MAX,
    };

    return wd_ip_set_test("wifidog-ng-mac", skb, &opt, state);
}

static inline int is_allowed_dest_ip(struct sk_buff *skb, const struct nf_hook_state *state)
{
    static struct ip_set_adt_opt opt = {
        .family = NFPROTO_IPV4,
        .dim = IPSET_DIM_ONE,
        .ext.timeout = UINT_MAX,
    };

    return wd_ip_set_test("wifidog-ng-ip", skb, &opt, state);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 17, 19)
static u32 wd_nat_setup_info(struct sk_buff *skb, struct nf_conn *ct)
#else
static u32 wd_nat_setup_info(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state, struct nf_conn *ct)
#endif
{
    struct tcphdr *tcph = tcp_hdr(skb);
    union nf_conntrack_man_proto proto;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 17, 19)
    struct nf_nat_range2 newrange = {};
    struct net *net = nf_ct_net(ct);
#else
    struct nf_nat_range newrange = {};
    struct net *net = state->net;
#endif
    struct wifidog_net *wd = net_generic(net, wd_net_id);
    static uint16_t PORT_80 = htons(80);

    proto.tcp.port = (tcph->dest == PORT_80) ? wd->port : wd->ssl_port;
    newrange.flags       = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
    newrange.min_addr.ip = wd->interface_ipaddr;
    newrange.max_addr.ip = wd->interface_ipaddr;
    newrange.min_proto   = proto;
    newrange.max_proto   = proto;

    ct->status |= IPS_HIJACKED;

    return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_DST);
}

static u32 wifidog_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct wifidog_net *wd = net_generic(state->net, wd_net_id);
    struct iphdr *iph = ip_hdr(skb);
    struct nf_conn *ct;
    struct tcphdr *tcph;
    struct udphdr *udph;
    enum ip_conntrack_info ctinfo;
    static uint16_t PORT_80 = htons(80);    /* http */
    static uint16_t PORT_443 = htons(443);  /* https */
    static uint16_t PORT_67 = htons(67);    /* dhcp */
    static uint16_t PORT_53 = htons(53);    /* dns */

    if (unlikely(!wd->enabled))
        return NF_ACCEPT;

    if (state->in->ifindex != wd->interface_ifindex)
        return NF_ACCEPT;

    /* Accept broadcast */
    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST)
        return NF_ACCEPT;

    /* Accept all to local area networks */
    if ((iph->daddr | ~wd->interface_mask) == wd->interface_broadcast)
        return NF_ACCEPT;

    ct = nf_ct_get(skb, &ctinfo);
    if (!ct || (ct->status & IPS_ALLOWED))
        return NF_ACCEPT;

    if (ct->status & IPS_HIJACKED) {
        if (is_allowed_mac(skb, state)) {
            /* Avoid duplication of authentication */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
            nf_reset(skb);
#else
            nf_reset_ct(skb);
#endif
            nf_ct_kill(ct);
        }
        return NF_ACCEPT;
    } else if (ctinfo == IP_CT_NEW && (is_allowed_dest_ip(skb, state) || is_allowed_mac(skb, state))) {
        ct->status |= IPS_ALLOWED;
        return NF_ACCEPT;
    }

    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = tcp_hdr(skb);
        if(tcph->dest == PORT_53 || tcph->dest == PORT_67) {
            ct->status |= IPS_ALLOWED;
            return NF_ACCEPT;
        }

        if (tcph->dest == PORT_80 || tcph->dest == PORT_443)
            goto redirect;
        else
            return NF_DROP;

    case IPPROTO_UDP:
        udph = udp_hdr(skb);
        if(udph->dest == PORT_53 || udph->dest == PORT_67) {
            ct->status |= IPS_ALLOWED;
            return NF_ACCEPT;
        }
        return NF_DROP;

    default:
        ct->status |= IPS_ALLOWED;
        return NF_ACCEPT;
    }

redirect:
    /* all packets from unknown client are dropped */
    if (ctinfo != IP_CT_NEW || (ct->status & IPS_DST_NAT_DONE)) {
        pr_debug("dropping packets of suspect stream, src:%pI4, dst:%pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 17, 19)
    return wd_nat_setup_info(skb, ct);
#else
    return nf_nat_ipv4_in(priv, skb, state, wd_nat_setup_info);
#endif
}

static struct nf_hook_ops wifidog_ops __read_mostly = {
    .hook       = wifidog_hook,
    .pf         = PF_INET,
    .hooknum    = NF_INET_PRE_ROUTING,
    .priority   = NF_IP_PRI_NAT_DST - 1
};

static int __net_init wd_net_init(struct net *net)
{
    struct wifidog_net *wd = net_generic(net, wd_net_id);
    int ret;

    wd->net = net;
    wd->interface_ifindex = -1;
    wd->port = htons(2060);
    wd->ssl_port = htons(8443);

    strcpy(wd->interface, "br-lan");

    wd->proc_dir = proc_mkdir(PROC_DIR_NAME, wd->net->proc_net);
    if (!wd->proc_dir) {
        pr_err("wifidog-ng: can't create dir /proc/net/"PROC_DIR_NAME"\n");
        return -ENODEV;;
    }

    if (!proc_create("config", 0644, wd->proc_dir, &proc_config_ops)) {
        pr_err("wifidog-ng: can't create file /proc/net/"PROC_DIR_NAME"/config\n");
        ret = -EINVAL;
        goto remove;
    }

    ret = nf_register_net_hook(net, &wifidog_ops);
    if (ret < 0) {
        pr_err("wifidog-ng: can't register hook\n");
        goto remove_config;
    }

    pr_info("wifidog-ng: Copyright (C) 2017 jianhui zhao <zhaojh329@gmail.com>\n");

    return 0;

remove_config:
	remove_proc_entry("config", wd->proc_dir);
remove:
	remove_proc_entry(PROC_DIR_NAME, wd->net->proc_net);
	return ret;
}

static void __net_exit wd_net_exit(struct net *net)
{
    struct wifidog_net *wd = net_generic(net, wd_net_id);

    remove_proc_entry("config", wd->proc_dir);
	remove_proc_entry(PROC_DIR_NAME, wd->net->proc_net);

    nf_unregister_net_hook(net, &wifidog_ops);
}

static struct pernet_operations wd_net_ops = {
	.init = wd_net_init,
	.exit = wd_net_exit,
	.id   = &wd_net_id,
	.size = sizeof(struct wifidog_net),
};

static int __init wifidog_init(void)
{
    return register_pernet_subsys(&wd_net_ops);
}

static void __exit wifidog_exit(void)
{
    unregister_pernet_subsys(&wd_net_ops);
}

module_init(wifidog_init);
module_exit(wifidog_exit);

MODULE_AUTHOR("jianhui zhao <zhaojh329@gmail.com>");
MODULE_LICENSE("GPL");

/*
 * Copyright (C) 2017 jianhui zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inetdevice.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "terminal.h"
#include "tip.h"

#define IPS_HIJACKED	(1 << 31)
#define IPS_ALLOWED		(1 << 30)

static struct proc_dir_entry *proc;
static char gw_interface[32] = "br-lan";
static int gw_interface_ifindex = -1;
static __be32 gw_interface_ipaddr;
static __be32 gw_interface_mask;
static __be32 gw_interface_broadcast;
static int gw_port = 2060;
static int gw_ssl_port = 8443;
static int wifidog_enabled;
static int wifidog_debug;

#define w_debug(fmt, arg...) {if (wifidog_debug) printk("[%s][%d]"fmt, __FILE__, __LINE__, ##arg);}

static int update_gw_interface(const char *interface)
{
	int ret = 0;
	struct net_device *dev;
	struct in_device *in_dev;
	
	dev = dev_get_by_name(&init_net, interface);
	if (!dev) {
		pr_err("Not found interface: %s\n", interface);
		return -ENOENT;
	}
	
	gw_interface_ifindex = dev->ifindex;
	
	in_dev = inetdev_by_index(dev_net(dev), gw_interface_ifindex);
	if (!in_dev) {
		pr_err("Not found in_dev on %s\n", interface);
		ret = -ENOENT;
		goto QUIT;
	}
	
	for_primary_ifa(in_dev) {
		gw_interface_ipaddr = ifa->ifa_local;
		gw_interface_mask = ifa->ifa_mask;
		gw_interface_broadcast = ifa->ifa_broadcast;
		
		pr_info("Found ip from %s: %pI4\n", interface, &gw_interface_ipaddr);
		break;
	} endfor_ifa(in_dev)
	
QUIT:	
	dev_put(dev);
	
	return ret;
}

static int proc_config_show(struct seq_file *s, void *v)
{
	seq_printf(s, "enabled(RW) = %d\n", wifidog_enabled);
	seq_printf(s, "interface(RW) = %s\n", gw_interface);
	seq_printf(s, "ifindex(RO) = %d\n", gw_interface_ifindex);
	seq_printf(s, "ipaddr(RO) = %pI4\n", &gw_interface_ipaddr);
	seq_printf(s, "netmask(RO) = %pI4\n", &gw_interface_mask);
	seq_printf(s, "broadcast(RO) = %pI4\n", &gw_interface_broadcast);
	seq_printf(s, "port(RW) = %d\n", gw_port);
	seq_printf(s, "ssl_port(RW) = %d\n", gw_ssl_port);
	seq_printf(s, "debug(RW) = %d\n", wifidog_debug);
	
	return 0;
}

static ssize_t proc_config_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	char data[128];
	char *delim, *key;
	const char *value;
	
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
		
		delim = strchr(value, ' ');
		if (delim)
			*delim++ = 0;
		
		if (!strcmp(key, "enabled"))
			wifidog_enabled = simple_strtol(value, NULL, 0);
		else if (!strcmp(key, "interface")) {
			strncpy(gw_interface, value, sizeof(gw_interface));
			update_gw_interface(gw_interface);
		} else if (!strcmp(key, "port")) {
			gw_port = simple_strtol(value, NULL, 0);
		} else if (!strcmp(key, "ssl_port")) {
			gw_ssl_port = simple_strtol(value, NULL, 0);
		} else if (!strcmp(key, "debug")) {
			wifidog_debug = simple_strtol(value, NULL, 0);
		}
		
		key = delim;
	}
			
	return size;
}

static int proc_config_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_config_show, NULL);
}

const static struct file_operations proc_config_ops = {
	.owner 		= THIS_MODULE,
	.open  		= proc_config_open,
	.read   	= seq_read,
	.write		= proc_config_write,
	.llseek 	= seq_lseek,
	.release 	= single_release
};

static u32 __nf_nat_setup_info(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct nf_conn *ct)
{
	struct tcphdr *tph = tcp_hdr(skb);
	union nf_conntrack_man_proto proto;
	struct nf_nat_range newrange;
	static uint16_t PORT_80 = htons(80);

	proto.tcp.port = (tph->dest == PORT_80) ? htons(gw_port) : htons(gw_ssl_port);
	newrange.flags	     = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	newrange.min_addr.ip = newrange.max_addr.ip = gw_interface_ipaddr;
	newrange.min_proto   = newrange.max_proto = proto;

	ct->status |= IPS_HIJACKED;

	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_DST);
}

static u32 wifidog_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct ethhdr *ehdr = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct nf_conn *ct;
	struct tcphdr *tph;
    struct udphdr *uph;
	struct terminal *term = NULL;
	enum ip_conntrack_info ctinfo;
	static uint16_t PORT_22 = htons(22);	/* ssh */
	static uint16_t PORT_80 = htons(80);	/* http */
	static uint16_t PORT_443 = htons(443);	/* https */
	static uint16_t PORT_53 = htons(53);	/* dns */
	static uint16_t PORT_123 = htons(123);	/* ntp */
	
	if (unlikely(!wifidog_enabled))
		return NF_ACCEPT;

	if (unlikely(state->in->ifindex != gw_interface_ifindex))
		return NF_ACCEPT;

	/* Accept all from non local area networks */
	if ((iph->saddr | ~gw_interface_mask) != gw_interface_broadcast)
		return NF_ACCEPT;

	term = find_term_by_ip(iph->saddr);
	if (likely(term)) {
		term->flags |= TERM_ACTIVE;
	} else {
		add_term(ehdr->h_source, iph->saddr);
	}

	/* Accept broadcast */
	if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST)
		return NF_ACCEPT;

	/* Accept to us */
	if (iph->daddr == gw_interface_ipaddr)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;

	if ((ct->status & IPS_HIJACKED) || (ct->status & IPS_ALLOWED)) {
		return NF_ACCEPT;
	} else if (ctinfo == IP_CT_NEW && (trusted_ip(iph->daddr) || term_is_authd(iph->saddr))) {
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
	struct iphdr *iph = ip_hdr(skb);
	struct terminal *term = NULL;
	__be32 saddr, daddr;
	u8 from_lan = 0;
	u8	to_lan = 0;
	
	if (ipv4_is_lbcast(iph->daddr) || ipv4_is_multicast(iph->saddr) 
		|| ipv4_is_multicast(iph->daddr)) {
			return NF_ACCEPT;
	}

	saddr = iph->saddr;
	daddr = iph->daddr;

	if ((saddr | ~gw_interface_mask) == gw_interface_broadcast)
		from_lan = 1;

	if ((daddr | ~gw_interface_mask) == gw_interface_broadcast)
		to_lan = 1;

	/* skip lan <-> lan & wan <-> wan */
	if (unlikely(from_lan == to_lan))
		return NF_ACCEPT;

	if (from_lan) {
		term = find_term_by_ip(saddr);
		if (unlikely(!term))
			return NF_ACCEPT;
	} else if (to_lan) {
		term = find_term_by_ip(daddr);
		if (unlikely(!term))
			return NF_ACCEPT;
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
		.hook		= wifidog_hook,
		.pf			= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK + 1 /* after conntrack */
	},
	{
		.hook		= term_statistic_hook,
		.pf			= PF_INET,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_LAST
	},
};

static int __init wifidog_init(void)
{
	int ret;

	update_gw_interface(gw_interface);
	
	proc = proc_mkdir("wifidog", NULL);
	if (!proc) {
		pr_err("can't create dir /proc/wifidog/\n");
		return -ENODEV;;
	}
	
	if (!proc_create("config", 0644, proc, &proc_config_ops)) {
		pr_err("can't create file /proc/wifidog/config\n");
		ret = -EINVAL;
		goto remove;
	}

	ret = term_init(proc);
	if (ret) {
		pr_err("term_init failed\n");
		goto remove_config;
	}
	
	ret = tip_init(proc);
	if (ret) {
		pr_err("tip_init failed\n");
		goto free_term;
	}

	ret = nf_register_hooks(wifidog_ops, ARRAY_SIZE(wifidog_ops));
	if (ret < 0) {
		pr_err("can't register hook\n");
		goto free_tip;
	}

	pr_info("kmod of wifidog is started\n");

	return 0;

free_tip:
	tip_free(proc);
free_term:
	term_free(proc);
remove_config:	
	remove_proc_entry("config", proc);
remove:
	remove_proc_entry("wifidog", NULL);
	return ret;
}

static void __exit wifidog_exit(void)
{
	term_free(proc);
	tip_free(proc);
	
	remove_proc_entry("config", proc);
	remove_proc_entry("wifidog", NULL);
	nf_unregister_hooks(wifidog_ops, ARRAY_SIZE(wifidog_ops));
	
	pr_info("kmod of wifidog is stop\n");
}

module_init(wifidog_init);
module_exit(wifidog_exit);

MODULE_AUTHOR("jianhui zhao <jianhuizhao329@gmail.com>");
MODULE_LICENSE("GPL");

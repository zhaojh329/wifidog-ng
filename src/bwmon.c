/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#include <pcap.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <libubox/ulog.h>
#include <libubox/uloop.h>

#include "term.h"
#include "bwmon.h"
#include "config.h"

static struct pcap *pd;
static struct uloop_fd ufd;

static void parse_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct config *conf = get_config();
	struct ethhdr *eth = (struct ethhdr *)sp;
	struct iphdr *iph = (struct iphdr *)(sp + 14);
	struct terminal *term;
	char mac_str[18];
	uint8_t *mac;

	mac = eth->h_source;
	sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	term = find_term(mac_str);
	if (term) {
		term->tx += iph->tot_len;
		goto done;
	}

	mac = eth->h_dest;
	sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	term = find_term(mac_str);
	if (term) {
		term->rx += iph->tot_len;
		goto done;
	}
	return;

done:
	if (term->flag & TERM_FLAG_AUTHED)
		uloop_timeout_set(&term->timeout, conf->checkinterval * conf->clienttimeout * 1000);
}

static void uloop_read_cb(struct uloop_fd *u, unsigned int events)
{
	pcap_dispatch(pd, -1, parse_packet, NULL);
}

int bwmon_init(const char *ifname)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 localnet, netmask;
	struct bpf_program fcode;

	pd = pcap_open_live(ifname, 14 + 20, 0, 0, ebuf);
    if (!pd) {
        ULOG_ERR("Unable to open device '%s': %s\n", ifname, ebuf);
        return -1;
    }

    pcap_lookupnet(ifname, &localnet, &netmask, ebuf);

    pcap_compile(pd, &fcode, "ip", 1, netmask);
    pcap_setfilter(pd, &fcode);

    if (pcap_setnonblock(pd, 1, ebuf) == -1) {
    	ULOG_ERR("pcap_setnonblock failed: %s\n", ebuf);	
    	goto err;
    }

	ufd.cb = uloop_read_cb;
	ufd.fd = pcap_get_selectable_fd(pd);
	uloop_fd_add(&ufd, ULOOP_READ);

	return 0;
err:
	pcap_close(pd);
	return -1;
}

void bwmon_deinit()
{
	if (!pd)
		return;
	pcap_close(pd);
	uloop_fd_delete(&ufd);
}

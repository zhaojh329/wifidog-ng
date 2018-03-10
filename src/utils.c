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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/time.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <libubox/ulog.h>
#include <netinet/ip_icmp.h>

#include "resolv.h"

int get_iface_ip(const char *ifname, char *dst, int len)
{
    struct ifreq ifr;
    int sock = -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        ULOG_ERR("socket:%s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        ULOG_ERR("ioctl:%s\n", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    snprintf(dst, len, "%s", inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr));
    
    return 0;
}

int get_iface_mac(const char *ifname, char *dst, int len)
{
    struct ifreq ifr;
    int sock;
    uint8_t *hw;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        ULOG_ERR("socket:%s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        ULOG_ERR("ioctl:%s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    close(sock);

    hw = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    snprintf(dst, len, "%02X%02X%02X%02X%02X%02X", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);

    return 0;
}

int arp_get(const char *ifname, const char *ip, char *dst, int len)
{
    struct arpreq req;  
    struct sockaddr_in *sin;  
    int sock = 0;
    uint8_t *hw;
  
    memset(&req, 0, sizeof(struct arpreq));  
  
    sin = (struct sockaddr_in *)&req.arp_pa;  
    sin->sin_family = AF_INET;  
    sin->sin_addr.s_addr = inet_addr(ip);  
  
    strncpy(req.arp_dev, ifname, sizeof(req.arp_dev));  
  
    sock = socket(AF_INET, SOCK_DGRAM, 0);  
    if(sock < 0) {
        ULOG_ERR("socket:%s\n", strerror(errno));  
        return -1;  
    }  
  
    if (ioctl(sock, SIOCGARP, &req) < 0) {
        ULOG_ERR("ioctl:%s\n", strerror(errno));  
        close(sock);  
        return -1;  
    }

    close(sock);

    hw = (uint8_t *)req.arp_ha.sa_data; 
    snprintf(dst, len, "%02X:%02X:%02X:%02X:%02X:%02X", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);

    return 0;
}

/* blen is the size of buf; slen is the length of src.  The input-string need
** not be, and the output string will not be, null-terminated.  Returns the
** length of the encoded string, or -1 on error (buffer overflow) */
int urlencode(char *buf, int blen, const char *src, int slen)
{
    static const char hex[] = "0123456789abcdef";
    int i, len = 0;

    blen -= 1;

    for (i = 0; (i < slen) && (len < blen); i++) {
        if(isalnum(src[i]) || (src[i] == '-') || (src[i] == '_') ||
            (src[i] == '.') || (src[i] == '~')) {
            buf[len++] = src[i];
        } else if ((len + 3) <= blen) {
            buf[len++] = '%';
            buf[len++] = hex[(src[i] >> 4) & 15];
            buf[len++] = hex[ src[i]       & 15];
        } else {
            len = -1;
            break;
        }
    }

    if (i == slen)
        buf[slen] = 0;
    return (i == slen) ? len : -1;
}

int allow_destip(const char *ip)
{
    FILE *fp = fopen("/proc/wifidog/ip", "w");
    if (!fp) {
        ULOG_ERR("Kernel module is not loaded\n");
        return -1;
    }

    fprintf(fp, "+%s\n", ip);
    fclose(fp);

    ULOG_INFO("allow destip: %s\n", ip);

    return 0;
}

int enable_kmod(const char *interface, int port, int ssl_port)
{
    FILE *fp = fopen("/proc/wifidog/config", "w");
    if (!fp) {
        ULOG_ERR("Kernel module is not loaded\n");
        return -1;
    }

    fprintf(fp, "interface=%s\n", interface);
    fprintf(fp, "port=%d\n", port);
    fprintf(fp, "ssl_port=%d\n", ssl_port);
    fprintf(fp, "enabled=1\n");
    fclose(fp);

    ULOG_INFO("Enable kmod\n");
    return 0;
}

int disable_kmod()
{
    FILE *fp = fopen("/proc/wifidog/config", "w");
    if (!fp) {
        ULOG_ERR("Kernel module is not loaded\n");
        return -1;
    }

    fprintf(fp, "enabled=0\n");
    fclose(fp);

    ULOG_INFO("Disable kmod\n");
    return 0;
}

static void my_resolv_cb(struct hostent *he, void *data)
{
    char **p;
    char addr_buf[INET_ADDRSTRLEN];

    for (p = he->h_addr_list; *p; p++) {
        inet_ntop(he->h_addrtype, *p, addr_buf, sizeof(addr_buf));
        allow_destip(addr_buf);
    }
}

int allow_domain(const char *domain)
{
    int ip[4];

    if (sscanf(domain, "%d.%d.%d.%d", ip + 0, ip + 1, ip + 2, ip + 3) == 4) {
        allow_destip(domain);
        return 0;
    }

    resolv_start(domain, my_resolv_cb, NULL);
    return 0;
}


/* Get a 16-bit unsigned random number. */
uint16_t rand16()
{
    static int been_seeded = 0;

    if (!been_seeded) {
        uint32_t seed = 0;
        struct timeval now;

        /* not a very good seed but what the heck, it needs to be quickly acquired */
        gettimeofday(&now, NULL);
        seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

        srand(seed);
        been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one. */
    return ((uint16_t)(rand() >> 15));
}

/*
 * note, to allow root to use icmp sockets, run:
 * sysctl -w net.ipv4.ping_group_range="0 0"
 */
int get_icmp_socket()
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        ULOG_ERR("get_icmp_socket error: %s\n", strerror(errno));
        return -1;
    }

    return sock;
}

/* Ping an IP. */
void icmp_ping(int sock, const char *ipaddr)
{
    struct sockaddr_in addr;
    struct icmphdr hdr = {
        .type = ICMP_ECHO
    };

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ipaddr);

    hdr.un.echo.id = rand16();

    if (sendto(sock, &hdr, sizeof(hdr), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ULOG_ERR("icmp_ping sendto(): %s\n", strerror(errno));
        return;
    }
}

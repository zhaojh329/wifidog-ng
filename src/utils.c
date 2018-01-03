/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <uhttpd/uhttpd.h>
#include "utils.h"

int get_iface_ip(const char *ifname, char *dst, int len)
{
    struct ifreq ifr;
    int sock = -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        uh_log_err("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        uh_log_err("ioctl");
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
        uh_log_err("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        uh_log_err("ioctl");
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
        uh_log_err("socket");  
        return -1;  
    }  
  
    if (ioctl(sock, SIOCGARP, &req) < 0) {
        uh_log_err("ioctl");  
        close(sock);  
        return -1;  
    }

    close(sock);

    hw = (uint8_t *)req.arp_ha.sa_data; 
    snprintf(dst, len, "%02X:%02X:%02X:%02X:%02X:%02X", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);

    return 0;
}

int enable_kmod(bool enable)
{
    FILE *fp = fopen("/proc/wifidog/config", "w");
    if (!fp) {
        uh_log_err("fopen");
        return -1;
    }

    fprintf(fp, "enabled=%d\n", enable ? 1 : 0);
    fclose(fp);
    return 0;
}

int allow_termianl(const char *mac)
{
    FILE *fp = fopen("/proc/wifidog/term", "w");
    if (!fp) {
        uh_log_err("fopen");
        return -1;
    }

    fprintf(fp, "+%s\n", mac);
    fclose(fp);

    uh_log_debug("allow termianl: %s", mac);
    return 0;
}

int deny_termianl(const char *mac)
{
    FILE *fp = fopen("/proc/wifidog/term", "w");
    if (!fp) {
        uh_log_err("fopen");
        return -1;
    }

    fprintf(fp, "-%s\n", mac);
    fclose(fp);

    uh_log_debug("allow termianl: %s", mac);
    return 0;
}

int allow_destip(const char *ip)
{
    FILE *fp = fopen("/proc/wifidog/ip", "w");
    if (!fp) {
        uh_log_err("fopen");
        return -1;
    }

    fprintf(fp, "+%s\n", ip);
    fclose(fp);

    uh_log_debug("allow destip: %s", ip);

    return 0;
}


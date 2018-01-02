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

#include "utils.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <string.h>
#include <stdio.h>   
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <sys/ioctl.h>  
#include <net/if_arp.h>  
#include <string.h>
#include <sys/sysinfo.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "config.h"
#include "httpget.h"
#include <uhttpd/uhttpd.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>

static time_t started_time;

char *get_iface_ip(const char *ifname)
{
    struct ifreq if_data;
    struct in_addr in;
    int sockd;
    u_int32_t ip;

    /* Create a socket */
    if ((sockd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        uh_log_err("socket");
        return NULL;
    }

     /* I want to get an IPv4 IP address */
    if_data.ifr_addr.sa_family = AF_INET;
    /* Get IP of internal interface */
    strncpy(if_data.ifr_name, ifname, 15);
    if_data.ifr_name[15] = '\0';

    /* Get the IP address */
    if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
        uh_log_err("ioctl");
        close(sockd);
        return NULL;
    }
    memcpy((void *)&ip, (void *)&if_data.ifr_addr.sa_data + 2, 4);
    in.s_addr = ip;

    close(sockd);
    return inet_ntoa(in);
}

char *get_iface_mac(const char *ifname)
{
    int r, s;
    struct ifreq ifr;
    char *hwaddr;
    static char mac[13];

    strncpy(ifr.ifr_name, ifname, 15);
    ifr.ifr_name[15] = '\0';

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
        uh_log_err("get_iface_mac socket: %s", strerror(errno));
        return NULL;
    }

    r = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (r == -1) {
        uh_log_err("get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
        close(s);
        return NULL;
    }

    hwaddr = ifr.ifr_hwaddr.sa_data;
    close(s);
    snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
             hwaddr[0] & 0xFF,
             hwaddr[1] & 0xFF, hwaddr[2] & 0xFF, hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

    return mac;
}


/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char *arp_get(const char *ifname, const char *ip)
{
	struct arpreq req;  
    struct sockaddr_in *sin;  
    int ret = 0;  
    int sock_fd = 0;
    char *mac;
    unsigned char *hw;
  
    memset(&req, 0, sizeof(struct arpreq));  
  
    sin = (struct sockaddr_in *)&req.arp_pa;  
    sin->sin_family = AF_INET;  
    sin->sin_addr.s_addr = inet_addr(ip);  
  
    //arp_dev长度为[16]，注意越界  
    strncpy(req.arp_dev, ifname, 15);  
  
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);  
    if(sock_fd < 0)  
    {  
        printf("get socket error.\n");  
        return NULL;  
    }  
  
    ret = ioctl(sock_fd, SIOCGARP, &req);  
    if(ret < 0)  
    {  
        perror("ioctl error.\n");  
        close(sock_fd);  
        return NULL;  
    }

    close(sock_fd);

    hw = (unsigned char *)req.arp_ha.sa_data; 
    asprintf(&mac, "%02X:%02X:%02X:%02X:%02X:%02X", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);

    return mac;
}

void check_internet_available()
{
    
}

static void heartbeat_cb(void *data, char *body)
{
    printf("Auth Server Says: %s\n", body);
}

static void heartbeat(struct uloop_timeout *t)
{
    struct config *conf = get_config();
    struct sysinfo info;

    memset(&info, 0, sizeof(info));
        
    if (sysinfo(&info) < 0)
        perror("sysinfo");
    
    httpget(heartbeat_cb, NULL, "http://%s:%d%s%sgw_id=%s&sys_uptime=%ld&sys_memfree=%lu&sys_load=%lu&wifidog_uptime=%lu",
        conf->authserver.host, conf->authserver.port, conf->authserver.path, conf->authserver.ping_path,
        conf->gw_id, info.uptime, info.freeram * info.mem_unit, info.loads[0], time(NULL) - started_time);
    
    uloop_timeout_set(t, 1000 * 2);
}

void start_heartbeat()
{
    static struct uloop_timeout timeout = {
        .cb = heartbeat
    };

    time(&started_time);
    
    uloop_timeout_set(&timeout, 0);
}

void enable_kmod(bool enable)
{
    FILE *fp = fopen("/proc/wifidog/config", "w");
    if (!fp)
        return;

    fprintf(fp, "enabled=%d\n", enable ? 1 : 0);

    fclose(fp);
}

void allow_termianl(const char *mac)
{
    FILE *fp = fopen("/proc/wifidog/term", "w");
    if (!fp)
        return;

    fprintf(fp, "+%s\n", mac);

    fclose(fp);

    uh_log_debug("allow termianl: %s", mac);
}

void allow_destip(const char *ip)
{
    FILE *fp = fopen("/proc/wifidog/ip", "w");
    if (!fp)
        return;

    fprintf(fp, "+%s\n", ip);

    fclose(fp);

    uh_log_debug("allow destip: %s", ip);
}


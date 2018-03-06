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
#include <netdb.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <libubox/ulog.h>
#include <libubox/runqueue.h>

static struct runqueue runq;

struct resolve_task {
    struct runqueue_process proc;
    char domain[0];
};

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
        ULOG_ERR("fopen:%s\n", strerror(errno));
        return -1;
    }

    fprintf(fp, "+%s\n", ip);
    fclose(fp);

    ULOG_INFO("allow destip: %s\n", ip);

    return 0;
}

void wifidog_runqueue_init()
{
    runqueue_init(&runq);
    runq.max_running_tasks = 1;
}

void wifidog_runqueue_finish()
{
    runqueue_kill(&runq);
}
int enable_kmod(const char *interface, int port, int ssl_port)
{
    FILE *fp = fopen("/proc/wifidog/config", "w");
    if (!fp) {
        ULOG_ERR("fopen:%s\n", strerror(errno));
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
        ULOG_ERR("fopen:%s\n", strerror(errno));
        return -1;
    }

    fprintf(fp, "enabled=0\n");
    fclose(fp);

    ULOG_INFO("Disable kmod\n");
    return 0;
}

static void resolve_run(struct runqueue *q, struct runqueue_task *t)
{
    struct resolve_task *r = container_of(t, struct resolve_task, proc.task);
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };
    struct addrinfo *result, *rp;
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        ULOG_ERR("resolve_run fork failed!\n");
        return;
    }

    if (pid) {
        runqueue_process_add(q, &r->proc, pid);
        return;
    }

    uloop_done();

    if (getaddrinfo(r->domain, NULL, &hints, &result))
        return;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            char ipbuf[16] = "";
            struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;

            ULOG_INFO("Resolve %s %s\n", r->domain, inet_ntop(AF_INET, &addr->sin_addr, ipbuf, 16));

            allow_destip(ipbuf);
        }
    }
}

static void resolve_complete(struct runqueue *q, struct runqueue_task *p)
{
    struct resolve_task *r = container_of(p, struct resolve_task, proc.task);

    ULOG_INFO("Resolve %s finish\n", r->domain);
    free(r);
}

int allow_domain(const char *domain)
{
    static const struct runqueue_task_type resolve_type = {
        .run = resolve_run,
        .cancel = runqueue_process_cancel_cb,
        .kill = runqueue_process_kill_cb
    };
    struct resolve_task *r;
    int ip[4];

    if (sscanf(domain, "%d.%d.%d.%d", ip + 0, ip + 1, ip + 2, ip + 3) == 4) {
        allow_destip(domain);
        return 0;
    }

    r = calloc(1, sizeof(struct resolve_task) + strlen(domain) + 1);
    if (!r) {
        ULOG_ERR("allow_domain failed: No mem\n");
        return -1;
    }

    r->proc.task.type = &resolve_type;
    r->proc.task.run_timeout = 500;
    r->proc.task.complete = resolve_complete;
    strcpy(r->domain, domain);
    runqueue_task_add(&runq, &r->proc.task, false);
    return 0;
}

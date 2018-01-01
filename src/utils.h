#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>

char *get_iface_ip(const char *ifname);
char *get_iface_mac(const char *ifname);

char *arp_get(const char *ifname, const char *ip);

void start_heartbeat();

void enable_kmod(bool enable);

void allow_termianl(const char *mac);
void allow_destip(const char *ip);

#endif

# wifidog-ng

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

next generation wifidog

wifidog-ng is a very efficient captive portal solution for wireless router which with
embedded linux(LEDE/Openwrt) system. 

It's referenced wifidog and apfree_wifidog, and it's a whole new one captive portal solution.
Unlike wifidog and apfree_wifidog, wifidog-ng does write kernel module to implement
authentication management instead of using iptables to create firewall rules.

## features:
* Compatible with original wifodog protocol
* Single threaded, Fully asynchronous, No blocking operation at all
* Writing kernel module to implement authentication management instead of using iptables to create firewall rules
* Support HTTPS
* Alternative OpenSSL and CyaSSl(wolfssl)

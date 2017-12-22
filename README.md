# WifiDog-ng

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libubox]: https://git.lede-project.org/?p=project/libubox.git
[WifiDog]: https://github.com/wifidog/wifidog-gateway

Next generation [WifiDog]

WifiDog-ng is a very efficient captive portal solution for wireless router which with
embedded linux(LEDE/Openwrt) system. 

## features:
* Compatible with original [WifiDog] protocol
* Based on [libubox]: Single threaded, Fully asynchronous, No blocking operation at all
* Writing kernel module to implement authentication management instead of using iptables to create firewall rules
* Support HTTPS: Alternative OpenSSL and CyaSSl(wolfssl)
* Support UBUS

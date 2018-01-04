# WifiDog-ng

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

[libuhttpd]: https://github.com/zhaojh329/libuhttpd
[libubox]: https://git.lede-project.org/?p=project/libubox.git
[libuclient]: https://git.lede-project.org/?p=project/uclient.git
[libuci]: https://git.lede-project.org/?p=project/uci.git
[WifiDog]: https://github.com/wifidog/wifidog-gateway

Next generation [WifiDog]

WifiDog-ng is a very efficient captive portal solution for wireless router which with
embedded linux(LEDE/Openwrt) system. 

`Keep Watching for More Actions on This Space`

# features:
* Compatible with original [WifiDog] protocol
* Based on [libubox]: Single threaded, Fully asynchronous, No blocking operation at all
* Writing kernel module to implement authentication management instead of using iptables to create firewall rules
* Support HTTPS: OpenSSL, mbedtls and CyaSSl(wolfssl)

# Dependencies
* [libubox]
* [libuhttpd]
* [libuclient]
* [libuci]

# How to use
add new feed into "feeds.conf.default":

    src-git libuhttpd https://github.com/zhaojh329/libuhttpd-feed.git
    src-git wifidog https://github.com/zhaojh329/wifidog-ng-feed.git

Install wifidog-ng packages:

    ./scripts/feeds update libuhttpd wifidog
    ./scripts/feeds install -a -p wifidog

Select package wifidog-ng in menuconfig and compile new image.

    Network  --->
        Captive Portals  --->
            <*> wifidog-ng-mbedtls.................................... wifidog-ng (mbedtls)
            < > wifidog-ng-nossl....................................... wifidog-ng (NO SSL)
            < > wifidog-ng-openssl.................................... wifidog-ng (openssl)
            < > wifidog-ng-wolfssl.................................... wifidog-ng (wolfssl)

# Contributing
If you would like to help making [wifidog-ng](https://github.com/zhaojh329/wifidog-ng) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING.md) file.

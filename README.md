# WifiDog-ng

![](https://img.shields.io/badge/license-LGPL2-brightgreen.svg?style=plastic "License")

[libuhttpd]: https://github.com/zhaojh329/libuhttpd
[libubox]: https://git.openwrt.org/?p=project/libubox.git
[libuclient]: https://git.openwrt.org/?p=project/uclient.git
[libuci]: https://git.openwrt.org/?p=project/uci.git
[WifiDog]: https://github.com/wifidog/wifidog-gateway
[pingcheck]: https://github.com/br101/pingcheck

Next generation [WifiDog]

WifiDog-ng is a very efficient captive portal solution for wireless router which with
embedded linux(LEDE/Openwrt) system. 

`Keep Watching for More Actions on This Space`

# Features
* Based on [libubox]: Single threaded, Fully asynchronous, No blocking operation at all
* Writing kernel module to implement authentication management instead of using iptables to create firewall rules
* Support HTTPS: OpenSSL, mbedtls and CyaSSl(wolfssl)

# Dependencies
* [libubox]
* [libuhttpd]
* [libuclient]
* [libuci]
* [pingcheck]

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

# UCI Config options
## Section gateway
| Name          | Type        | Required  | Default   | Description |
| ------------- | ----------- | --------- | ----------| ----------- |
| enabled       | bool        | no        | 0         | Whether to enable wifidog |
| ifname        | interface   | no        | br-lan    | Interface to listen by wifidog |
| port          | port number | no        | 2060      | port to listen by wifidog |
| ssl_port      | port number | no        | 8443      | ssl port to listen by wifidog |
| checkinterval | seconds     | no        | 30        |  |
| temppass_time | seconds     | no        | 30        |  |

## Section authserver
| Name        | Required  | Default         |
| ------------| --------- | ----------------|
| host        | yes       | no              |
| port        | no        | 80              |
| path        | no        | /wifidog        |
| login_path  | no        | login?          |
| portal_path | no        | portal?         |
| msg_path    | no        | gw_message.php? |
| ping_path   | no        | ping?           |
| auth_path   | no        | auth?           |

# Contributing
If you would like to help making [wifidog-ng](https://github.com/zhaojh329/wifidog-ng) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING.md) file.

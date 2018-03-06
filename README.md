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
* Based on [libubox] - Use epoll
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
| Name           | Type        | Required  | Default   | Description |
| -------------- | ----------- | --------- | ----------| ----------- |
| enabled        | bool        | no        | 0         | Whether to enable wifidog |
| ifname         | interface   | no        | br-lan    | Interface to listen by wifidog |
| port           | port number | no        | 2060      | port to listen by wifidog |
| ssl_port       | port number | no        | 8443      | ssl port to listen by wifidog |
| checkinterval  | seconds     | no        | 30        | How many seconds should we wait between timeout checks. This is also how often the gateway will ping the auth server and how often it will update the traffic counters on the auth server.|
| temppass_time  | seconds     | no        | 30        | Temporary pass time |
| client_timeout | seconds     | no        | 5         | Set this to the desired of number of CheckInterval of inactivity before a client is logged out. The timeout will be INTERVAL * TIMEOUT |

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

# Protocol
## Gateway heartbeating (Ping Protocol)
`http://authserver/wifidog/ping?gw_id=xx&sys_uptime=xx&sys_memfree=xx&sys_load=xx&wifidog_uptime=xx`

To this the auth server is expected to respond with an http message containing the word "Pong".

## Login
`http://authserver/wifidog/login?gw_address=xx&gw_port=xx&gw_id=xx&ip=xx&mac=xx&ssid=xx&url=xx`

## Auth
`http://gw_address:gw_port/wifidog/auth?token=xx`

## Auth confirm
`http://authserver/wifidog/auth?stage=login&ip=xx&max=xx&token=xx&incoming=xx&outgoing=xx`

The response of the auth server should be "Auth: 1" or "Auth: 0"

## Counters (POST)
`http://authserver/wifidog/auth/?stage=counters&gw_id=xx`

```
{
    "counters":[{
        "ip": "192.168.1.201",
        "mac": "xx:xx:xx:xx:xx:xx",
        "token": "eb6d8d7f5ad6f35553a40f66cd2bff70",
        "incoming": 4916,
        "outgoing": 20408
    }, {
        "ip": "192.168.1.202",
        "mac": "xx:xx:xx:xx:xx:xx",
        "token": "eb6d8d7f5ad6f35553a40f66cd2bff70",
        "incoming": 4916,
        "outgoing": 20408
    }]
}
```

The response of the server should be:

```
{
    "resp":[{
        "mac": "0c:1d:ff:c4:db:fc",
        "auth": 1
    }, {
        "mac": "0c:1d:cf:c4:db:fc",
        "auth": 0
    }]
}
```

## Temporary pass
`http://gw_address:gw_port/wifidog/temppass?script=startWeChatAuth();`

# Contributing
If you would like to help making [wifidog-ng](https://github.com/zhaojh329/wifidog-ng) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING.md) file.

# WifiDog-ng([中文](/README_ZH.md))

[1]: https://img.shields.io/badge/license-LGPL2-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/wifidog-ng/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/wifidog-ng/issues/new
[7]: https://img.shields.io/badge/release-1.5.0-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/wifidog-ng/releases
[9]: https://travis-ci.org/zhaojh329/wifidog-ng.svg?branch=master
[10]: https://travis-ci.org/zhaojh329/wifidog-ng

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
[![Build Status][9]][10]

[libuhttpd]: https://github.com/zhaojh329/libuhttpd
[libubox]: https://git.openwrt.org/?p=project/libubox.git
[libuclient]: https://git.openwrt.org/?p=project/uclient.git
[libuci]: https://git.openwrt.org/?p=project/uci.git
[WifiDog]: https://github.com/wifidog/wifidog-gateway
[c-ares]: https://github.com/c-ares/c-ares
[rtty]: https://github.com/zhaojh329/rtty
[ipset]: http://ipset.netfilter.org
[libpcap]: http://www.us.tcpdump.org

Next generation [WifiDog]

WifiDog-ng is a very efficient captive portal solution for wireless router which with
embedded linux(LEDE/Openwrt) system. 

`Keep Watching for More Actions on This Space`

# Features
* Use epoll - Based on [libubox]: Single threaded, Fully asynchronous, No blocking operation at all
* Use ipset and writing kernel module to implement authentication management instead of using iptables to create firewall rules
* Support HTTPS: OpenSSL, mbedtls and CyaSSl(wolfssl)
* Remote configuration(With the help of [rtty])
* Support roam
* Code structure is concise and understandable

# Dependencies
* [libubox]
* [libuhttpd]
* [libuclient]
* [libuci]
* [c-ares]
* [ipset]
* [libpcap]

# Install on OpenWrt
    opkg update
    opkg list | grep wifidog-ng
    opkg install wifidog-ng-nossl

If the install command fails, you can [compile it yourself](/BUILDOPENWRT.md).

# UCI Config options
## Section gateway
| Name           | Type        | Required  | Default | Description |
| -------------- | ----------- | --------- | ------- | ------- |
| enabled        | bool        | no        | 0       | Whether to enable wifidog |
| id             | string      | no        |         | Gateway id. If not set, the mac address of the ifname will be used |
| ifname         | interface   | no        | br-lan  | Interface to listen by wifidog |
| port           | port number | no        | 2060    | port to listen by wifidog |
| ssl_port       | port number | no        | 8443    | ssl port to listen by wifidog |
| ssid           | ssid        | no        |         | Used for WeChat |
| checkinterval  | seconds     | no        | 30      | How many seconds should we wait between timeout checks. This is also how often the gateway will ping the auth server and how often it will update the traffic counters on the auth server.|
| temppass_time  | seconds     | no        | 30      | Temporary pass time |
| client_timeout | seconds     | no        | 5       | Set this to the desired of number of CheckInterval of inactivity before a client is logged out. The timeout will be INTERVAL * TIMEOUT |

## Section authserver
| Name        | Type        | Required  | Default         |
| ----------- | ----------- | --------- | --------------- |
| host        | string      | yes       | no              |
| port        | port number | no        | 80              |
| ssl         | bool        | no        | 0               |
| path        | string      | no        | /wifidog        |
| login_path  | string      | no        | login           |
| portal_path | string      | no        | portal          |
| msg_path    | string      | no        | gw_message.php  |
| ping_path   | string      | no        | ping            |
| auth_path   | string      | no        | auth            |

## Section popularserver
| Name    | Type | Required  | Default                    |
| ------- | ---- | --------- | -------------------------- |
| server  | list | no        | `www.baidu.com www.qq.com` |

## Section whitelist
| Name   | Type | Description               | 
| ------ | ---- | ------------------------- |
| domain | list | Can be a domain or ipaddr |
| mac    | list | A macaddr                 |

# Protocol
## Gateway heartbeating (Ping Protocol)
`http://authserver/wifidog/ping?gw_id=xx&sys_uptime=xx&sys_memfree=xx&sys_load=xx&wifidog_uptime=xx`

To this the auth server is expected to respond with an http message containing the word "Pong".

## Login
`http://authserver/wifidog/login?gw_address=xx&gw_port=xx&gw_id=xx&ip=xx&mac=xx&ssid=xx`

## Auth
`http://gw_address:gw_port/wifidog/auth?token=xx`

## Auth confirm
`http://authserver/wifidog/auth?stage=login&ip=xx&max=xx&token=xx&incoming=xx&outgoing=xx`

The response of the auth server should be "Auth: 1" or "Auth: 0"

## Roam
`http://authserver/wifidog/auth?stage=roam&ip=xx&max=xx`

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
        "outgoing": 20408,
        "uptime": 23223
    }, {
        "ip": "192.168.1.202",
        "mac": "xx:xx:xx:xx:xx:xx",
        "token": "eb6d8d7f5ad6f35553a40f66cd2bff70",
        "incoming": 4916,
        "outgoing": 20408,
        "uptime": 23223
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

# [Test Server](https://github.com/zhaojh329/wifidog-ng-authserver)

# Remote configuration(First install [rtty])
wifidog-ng provides the UBUS configuration interface and then remotely configuring the wifidog-ng with the help of the remote execution command of the [rtty]

    # ubus -v list wifidog-ng
    'wifidog-ng' @5903037c
        "term":{"action":"String","mac":"String"}
        "config":{"type":"String","options":"Table"}
        "whitelist":{"action":"String","domain":"String","mac":"String"}

## Allow client

    ubus call wifidog-ng term '{"action":"add", "mac":"11:22:33:44:55:66"}'

## Kick off client

    ubus call wifidog-ng term '{"action":"del", "mac":"11:22:33:44:55:66"}'

## Add domain whitelist

    ubus call wifidog-ng whitelist '{"action":"add", "type":"domain", "value":"qq.com"}'

## Delete domain whitelist

    ubus call wifidog-ng whitelist '{"action":"del", "type":"domain", "value":"qq.com"}'

## Add macaddr whitelist

    ubus call wifidog-ng whitelist '{"action":"add", "type":"mac", "value":"11:22:33:44:55:66"}'

## Delete macaddr whitelist

    ubus call wifidog-ng whitelist '{"action":"del", "type":"mac", "value":"11:22:33:44:55:66"}'

## Show terminal list

    ubus call wifidog-ng term '{"action":"show"}'

## Remote configuration example

    #!/bin/sh

    host="your-rtty-server.com"
    port=5912
    devid="test"
    username="root"
    password="123456"
    action="add"
    domain="www.163.com"

    params="[\"call\", \"wifidog-ng\", \"whitelist\", \"{\\\"action\\\":\\\"$action\\\", \\\"domain\\\":\\\"$domain\\\"}\"]"

    data="{\"devid\":\"$devid\",\"username\":\"$username\",\"password\":\"$password\",\"cmd\":\"ubus\",\"params\":$params}"

    echo $data
    curl -k "https://$host:$port/cmd" -d "$data"

# Contributing
If you would like to help making [wifidog-ng](https://github.com/zhaojh329/wifidog-ng) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING.md) file.

# QQ group: 153530783

# If the project is helpful to you, please do not hesitate to star. Thank you!

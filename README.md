# WifiDog-ng([中文](/README_ZH.md))

[1]: https://img.shields.io/badge/license-LGPL2-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/wifidog-ng/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/wifidog-ng/issues/new
[7]: https://img.shields.io/badge/release-2.0.0-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/wifidog-ng/releases

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]

Next generation WifiDog

WifiDog-ng is a very efficient captive portal solution for wireless router which with
embedded linux(LEDE/Openwrt) system implemented in Lua.

`Keep Watching for More Actions on This Space`

# Features
* Written in Lua, so development is very efficient
* Use ipset and writing kernel module to implement authentication management instead of using iptables to create firewall rules
* Support roam
* Code structure is concise and understandable

# [Build](/BUILD.md)

# UCI Config options
## Section gateway
| Name           | Type        | Required  | Default | Description |
| -------------- | ----------- | --------- | ------- | ------- |
| enabled        | bool        | no        | 0       | Whether to enable wifidog |
| dhcp_host_white| bool        | no        | 1       | dhcp mac is whitelist |
| id             | string      | no        |         | Gateway id. If not set, the mac address of the ifname will be used |
| interface      | Openwrt interface  | no      | lan  | The device belong to the interface to listen by wifidog |
| port           | port number | no        | 2060    | port to listen by wifidog |
| ssl_port       | port number | no        | 8443    | ssl port to listen by wifidog |
| ssid           | ssid        | no        |         | Used for WeChat |
| checkinterval  | seconds     | no        | 30      | How often the gateway will ping the auth server |
| temppass_time  | seconds     | no        | 30      | Temporary pass time |

## Section server
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

## Section validated_user

| Name    | Type   | Description         | 
| ------- | ------ | ------------------- |
| mac     | string | A macaddr           |
| comment | string | A comment           |

## Section validated_domain
| Name    | Type   | Description               | 
| ------- | ------ | ------------------------- |
| domain  | string | Can be a domain or ipaddr |
| comment | string | A comment                 |

# Protocol
## Gateway heartbeating (Ping Protocol)
`http://authserver/wifidog/ping?gw_id=xx&sys_uptime=xx&sys_memfree=xx&sys_load=xx&wifidog_uptime=xx`

To this the auth server is expected to respond with an http message containing the word "Pong".

## Login
`http://authserver/wifidog/login?gw_address=xx&gw_port=xx&gw_id=xx&ip=xx&mac=xx&ssid=xx`

## Auth
`http://gw_address:gw_port/wifidog/auth?token=xx`

## Auth confirm
`http://authserver/wifidog/auth?stage=login&ip=xx&mac=xx&token=xx&incoming=xx&outgoing=xx`

The response of the auth server should be "Auth: 1" or "Auth: 0"

## Roam
`http://authserver/wifidog/auth?stage=roam&ip=xx&max=xx`

The response of the auth server should be "token=xxxxxxx" or other.

## Temporary pass
`http://gw_address:gw_port/wifidog/temppass?script=startWeChatAuth();`

# [Test Server](https://github.com/zhaojh329/wifidog-ng-authserver)

# Manage
## Kick off the term

    wget "http://lanip:2060/wifidog/ctl?op=kick&mac=0C:1D:AF:C4:DB:FC" -O /dev/null

## Relaod config

    wget "http://lanip:2060/wifidog/ctl?op=reload" -O /dev/null

## Show device

    ipset list wifidog-ng-mac

# [Donate](https://gitee.com/zhaojh329/wifidog-ng#project-donate-overview)

# Contributing
If you would like to help making [wifidog-ng](https://github.com/zhaojh329/wifidog-ng) better,
see the [CONTRIBUTING.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING.md) file.

# QQ group: 153530783

# If the project is helpful to you, please do not hesitate to star. Thank you!

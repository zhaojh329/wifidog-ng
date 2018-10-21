# WifiDog-ng

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

WifiDog-ng一个非常高效的无线热点认证解决方案。使用Lua实现。

`请保持关注以获取最新的项目动态`

# 特性
* 采用Lua编写，即改即得，开发效率非常高
* 使用ipset以及编写内核模块实现认证管理，而不是使用iptables创建防火墙规则
* 支持漫游
* 代码结构清晰，通俗易懂

# [编译](/BUILD.md)

# UCI配置选项
## Section gateway
| 名称           | 类型        | 是否必须  | 默认值   | 描述 |
| -------------- | ----------- | --------- | -------- | ----------- |
| enabled        | bool        | no        | 0        | 是否开启wifidog-ng |
| dhcp_host_white| bool        | no        | 1        | dhcp中的mac为白名单 |
| id             | string      | no        |          | 网关ID，如果未设置，将使用ifname的macaddr |
| interface      | Openwrt interface   | no        | lan   | wifidog-ng监听接口 |
| port           | port number | no        | 2060     | wifidog-ng监听端口 |
| ssl_port       | port number | no        | 8443     | wifidog-ng监听端口（ssl) |
| ssid           | ssid        | no        |          | 用于微信认证 |
| checkinterval  | seconds     | no        | 30       | 心跳间隔 |
| temppass_time  | seconds     | no        | 30       | 临时放行时间 |

## Section server
| 名称        | 类型        | 是否必须  | 默认值          |
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

| 名称    | 类型   | 描述                   |
| ------- | ------ | --------------------- |
| mac     | string | mac地址               |
| comment | string | 注释                  |

## Section validated_domain
| 名称   | 类型    | 描述                    |
| ------ | ------- | ---------------------- |
| domain | string  | 可以是一个域名或者ip地址 |
| comment | string | 注释                    |

# 协议
## 网关心跳
`http://authserver/wifidog/ping?gw_id=xx&sys_uptime=xx&sys_memfree=xx&sys_load=xx&wifidog_uptime=xx`

认证服务器应返回：Pong

## 登录
`http://authserver/wifidog/login?gw_address=xx&gw_port=xx&gw_id=xx&ip=xx&mac=xx&ssid=xx`

## 认证
`http://gw_address:gw_port/wifidog/auth?token=xx`

## 认证确认
`http://authserver/wifidog/auth?stage=login&ip=xx&mac=xx&token=xx&incoming=xx&outgoing=xx`

认证服务器应返回："Auth: 1" 或者 "Auth: 0"

## 漫游
`http://authserver/wifidog/auth?stage=roam&ip=xx&max=xx`

认证服务器应返回：""token=xxxxxxx" 或者其它任意字符串

## 临时放行
`http://gw_address:gw_port/wifidog/temppass?script=startWeChatAuth();`

# [测试服务器](https://github.com/zhaojh329/wifidog-ng-authserver)

# 管理
## 踢终端下线

    wget "http://lanip:2060/wifidog/ctl?op=kick&mac=0C:1D:AF:C4:DB:FC" -O /dev/null

## 重载配置

    wget "http://lanip:2060/wifidog/ctl?op=reload" -O /dev/null

## 查看在线终端

    ipset list wifidog-ng-mac

# 谁在使用wifidog-ng

# [捐赠](https://gitee.com/zhaojh329/wifidog-ng#project-donate-overview)

# 贡献代码
如果你想帮助[wifidog-ng](https://github.com/zhaojh329/wifidog-ng)变得更好，请参考
[CONTRIBUTING_ZH.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING_ZH.md)。

# 技术交流
QQ群：153530783

# 如果该项目对您有帮助，请随手star，谢谢！

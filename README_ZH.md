# WifiDog-ng

[1]: https://img.shields.io/badge/license-LGPL2-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/wifidog-ng/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/wifidog-ng/issues/new
[7]: https://img.shields.io/badge/release-1.2.0-blue.svg?style=plastic
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

WifiDog-ng一个非常高效的无线热点认证解决方案。

`请保持关注以获取最新的项目动态`

# 特性
* 使用epoll - 基于[libubox]：单线程，全异步
* 编写内核模块实现认证管理，而不是使用iptables创建防火墙规则
* 支持HTTPS：OpenSSL, mbedtls and CyaSSl(wolfssl)
* 代码结构清晰，通俗易懂

# 依赖
* [libubox]
* [libuhttpd]
* [libuclient]
* [libuci]
* [c-ares]

# 安装到OpenWRT
    opkg update
    opkg list | grep wifidog-ng
    opkg install wifidog-ng-nossl

如果安装失败，你可以[自己编译](/BUILDOPENWRT_ZH.md)。

# UCI配置选项
## Section gateway
| 名称           | 类型        | 是否必须  | 默认值   | 描述 |
| -------------- | ----------- | --------- | -------- | ----------- |
| enabled        | bool        | no        | 0        | 是否开启wifidog-ng |
| id             | string      | no        |          | 网关ID，如果未设置，将使用ifname的macaddr |
| ifname         | interface   | no        | br-lan   | wifidog-ng监听接口 |
| port           | port number | no        | 2060     | wifidog-ng监听端口 |
| ssl_port       | port number | no        | 8443     | wifidog-ng监听端口（ssl) |
| ssid           | ssid        | no        |          | 用于微信认证 |
| checkinterval  | seconds     | no        | 30       | 超时检查时间间隔。也作为心跳间隔，以及流量统计间隔 |
| temppass_time  | seconds     | no        | 30       | 临时放行时间 |
| client_timeout | seconds     | no        | 5        | 客户端超时下线时间：checkinterval * client_timeout |

## Section authserver
| 名称        | 是否必须  | 默认值         |
| ------------| --------- | ----------------|
| host        | yes       | no              |
| port        | no        | 80              |
| path        | no        | /wifidog        |
| login_path  | no        | login           |
| portal_path | no        | portal          |
| msg_path    | no        | gw_message.php  |
| ping_path   | no        | ping            |
| auth_path   | no        | auth            |

## Section popularserver
| 名称    | 类型 | 是否必须  | 默认值                    |
| ------- | ---- | --------- | -------------------------- |
| server  | list | no        | `www.baidu.com www.qq.com` |

# 协议
## 网关心跳
`http://authserver/wifidog/ping?gw_id=xx&sys_uptime=xx&sys_memfree=xx&sys_load=xx&wifidog_uptime=xx`

认证服务器应返回：Pong

## 登录
`http://authserver/wifidog/login?gw_address=xx&gw_port=xx&gw_id=xx&ip=xx&mac=xx&ssid=xx&url=xx`

## 认证
`http://gw_address:gw_port/wifidog/auth?token=xx`

## 认证确认
`http://authserver/wifidog/auth?stage=login&ip=xx&max=xx&token=xx&incoming=xx&outgoing=xx`

认证服务器应返回："Auth: 1" 或者 "Auth: 0"

## 流量统计(POST)
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

认证服务器应返回如下格式：

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

## 临时放行
`http://gw_address:gw_port/wifidog/temppass?script=startWeChatAuth();`

# [测试服务器](https://github.com/zhaojh329/wifidog-ng-authserver)

# 贡献代码
如果你想帮助[wifidog-ng](https://github.com/zhaojh329/wifidog-ng)变得更好，请参考
[CONTRIBUTING_ZH.md](https://github.com/zhaojh329/wifidog-ng/blob/master/CONTRIBUTING_ZH.md)。

# 技术交流
QQ群：153530783

# 如果该项目对您有帮助，请随手star，谢谢！

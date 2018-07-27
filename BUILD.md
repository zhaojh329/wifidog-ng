# Openwrt master

Update feeds

    ./scripts/feeds update -a
    ./scripts/feeds install -a

Select wifidog-ng in menuconfig and compile new image.

	Network  --->
        Captive Portals  --->
            <*> wifidog-ng-mbedtls.................................... wifidog-ng (mbedtls)
            < > wifidog-ng-nossl....................................... wifidog-ng (NO SSL)
            < > wifidog-ng-openssl.................................... wifidog-ng (openssl)
            < > wifidog-ng-wolfssl.................................... wifidog-ng (wolfssl)

# [Openwrt 14.04](https://github.com/zhaojh329/wifidog-ng/blob/openwrt-14.04/README.md)

# [Openwrt 15.05](https://github.com/zhaojh329/wifidog-ng/blob/openwrt-15.05/README.md)

# [Lede](https://github.com/zhaojh329/wifidog-ng/blob/openwrt-lede/README.md)

# [Openwrt 18.06](https://github.com/zhaojh329/wifidog-ng/blob/openwrt-18/README.md)

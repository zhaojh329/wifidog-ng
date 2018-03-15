更新feeds

    ./scripts/feeds update -a
    ./scripts/feeds install -a

在menuconfig中选择wifidog-ng，然后重新编译固件

	Network  --->
        Captive Portals  --->
            <*> wifidog-ng-mbedtls.................................... wifidog-ng (mbedtls)
            < > wifidog-ng-nossl....................................... wifidog-ng (NO SSL)
            < > wifidog-ng-openssl.................................... wifidog-ng (openssl)
            < > wifidog-ng-wolfssl.................................... wifidog-ng (wolfssl)
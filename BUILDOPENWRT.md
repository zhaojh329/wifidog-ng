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
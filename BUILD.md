# Openwrt master

Update feeds

    ./scripts/feeds update -a
    ./scripts/feeds install -a

Select wifidog-ng in menuconfig and compile new image.

	Network  --->
        Captive Portals  --->
            <*> wifidog-ng.................................... wifidog-ng

# Other

Add feeds

	echo 'src-git wifidog_ng https://github.com/zhaojh329/wifidog-ng.git' >> feeds.conf.default

Update feeds

	./scripts/feeds uninstall -a
	./scripts/feeds update wifidog_ng
	./scripts/feeds install -a -f -p wifidog_ng
	./scripts/feeds install -a

Select wifidog-ng in menuconfig and compile new image.

	Network  --->
        Captive Portals  --->
            <*> wifidog-ng.................................... wifidog-ng
# Openwrt master

Update feeds

    ./scripts/feeds update -a
    ./scripts/feeds install -a

Select wifidog-ng in menuconfig and compile new image.

	Network  --->
        Captive Portals  --->
            <*> wifidog-ng.................................... wifidog-ng

# Other

Clone code

	rm -rf feeds/packages/net/wifidog-ng
	cd package/network
	git clone https://github.com/zhaojh329/wifidog-ng.git

Select wifidog-ng in menuconfig and compile new image.

	Network  --->
        Captive Portals  --->
            <*> wifidog-ng.................................... wifidog-ng
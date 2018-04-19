add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE)

# The version number.
set(WIFIDOG_NG_VERSION_MAJOR 1)
set(WIFIDOG_NG_VERSION_MINOR 5)
set(WIFIDOG_NG_VERSION_PATCH 6)

# Check the third party Libraries
find_package(Libubox REQUIRED)
find_package(Libuhttpd REQUIRED)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${LIBUHTTPD_INCLUDE_DIR}
	${LIBUBOX_INCLUDE_DIR}
)
set(EXTRA_LIBS ${LIBUHTTPD_LIBRARY} ${LIBUBOX_LIBRARY} uci uclient
	blobmsg_json ubus cares ipset pcap dl)

add_executable(wifidog-ng main.c auth.c utils.c config.c http.c
	heartbeat.c counters.c ubus.c resolv.c check_internet.c
	ipset.c term.c bwmon.c)

target_link_libraries(wifidog-ng ${EXTRA_LIBS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
	${CMAKE_CURRENT_BINARY_DIR}/version.h
)

install(
    TARGETS wifidog-ng
    RUNTIME DESTINATION bin
)

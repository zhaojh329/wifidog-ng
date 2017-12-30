add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE)

# Check the third party Libraries
find_package(Libubox REQUIRED)
find_package(Libuhttpd REQUIRED)

include_directories(${LIBUHTTPD_INCLUDE_DIR} ${LIBUBOX_INCLUDE_DIR})
set(EXTRA_LIBS ${LIBUHTTPD_LIBRARY} ${LIBUBOX_LIBRARY})

add_executable(wifidog-ng main.c)
target_link_libraries(wifidog-ng ${EXTRA_LIBS})

install(
    TARGETS wifidog-ng
    RUNTIME DESTINATION bin
)

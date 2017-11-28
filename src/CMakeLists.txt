cmake_minimum_required(VERSION 2.8)

project(wifidog-ng C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

#set(CMAKE_VERBOSE_MAKEFILE ON)

add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE)

# Check the third party Libraries
find_package(Libev REQUIRED)
find_package(Libuhttp REQUIRED)

include_directories(${LIBUHTTP_INCLUDE_DIRS} ${LIBEV_INCLUDE_DIRS})
set(EXTRA_LIBS ${LIBUHTTP_LIBRARIES} ${LIBEV_LIBRARIES})

add_executable(wifidog main.c)
target_link_libraries(wifidog ${EXTRA_LIBS})

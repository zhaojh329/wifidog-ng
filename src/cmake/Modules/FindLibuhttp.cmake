# - Try to find libuhttp
# Once done this will define
#  LIBUHTTP_FOUND        - System has libuhttp
#  LIBUHTTP_INCLUDE_DIRS - The libuhttp include directories
#  LIBUHTTP_LIBRARIES    - The libraries needed to use libuhttp

find_path(LIBUHTTP_INCLUDE_DIR uhttp.h)
find_library(LIBUHTTP_LIBRARY uhttp PATH_SUFFIXES lib64)

if(LIBUHTTP_INCLUDE_DIR)
  file(STRINGS "${LIBUHTTP_INCLUDE_DIR}/uhttp.h"
      LIBUHTTP_VERSION_MAJOR REGEX "^#define[ \t]+UHTTP_VERSION_MAJOR[ \t]+[0-9]+")
  file(STRINGS "${LIBUHTTP_INCLUDE_DIR}/uhttp.h"
      LIBUHTTP_VERSION_MINOR REGEX "^#define[ \t]+UHTTP_VERSION_MINOR[ \t]+[0-9]+")
  string(REGEX REPLACE "[^0-9]+" "" LIBUHTTP_VERSION_MAJOR "${LIBUHTTP_VERSION_MAJOR}")
  string(REGEX REPLACE "[^0-9]+" "" LIBUHTTP_VERSION_MINOR "${LIBUHTTP_VERSION_MINOR}")
  set(LIBUHTTP_VERSION "${LIBUHTTP_VERSION_MAJOR}.${LIBUHTTP_VERSION_MINOR}")
  unset(LIBUHTTP_VERSION_MINOR)
  unset(LIBUHTTP_VERSION_MAJOR)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBUHTTP_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(Libuhttp REQUIRED_VARS
                                  LIBUHTTP_LIBRARY LIBUHTTP_INCLUDE_DIR
                                  VERSION_VAR LIBUHTTP_VERSION)

if(LIBUHTTP_FOUND)
  set(LIBUHTTP_LIBRARIES     ${LIBUHTTP_LIBRARY})
  set(LIBUHTTP_INCLUDE_DIRS  ${LIBUHTTP_INCLUDE_DIR})
endif()

mark_as_advanced(LIBUHTTP_INCLUDE_DIR LIBUHTTP_LIBRARY)

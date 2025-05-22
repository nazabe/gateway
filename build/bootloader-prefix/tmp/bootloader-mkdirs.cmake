# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/nazareno/esp/esp-idf/components/bootloader/subproject"
  "/home/nazareno/espressif/gateway/build/bootloader"
  "/home/nazareno/espressif/gateway/build/bootloader-prefix"
  "/home/nazareno/espressif/gateway/build/bootloader-prefix/tmp"
  "/home/nazareno/espressif/gateway/build/bootloader-prefix/src/bootloader-stamp"
  "/home/nazareno/espressif/gateway/build/bootloader-prefix/src"
  "/home/nazareno/espressif/gateway/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/nazareno/espressif/gateway/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/nazareno/espressif/gateway/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()

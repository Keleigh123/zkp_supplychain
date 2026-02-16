# Install script for directory: /home/keleigh/longfellow-zk/lib

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/keleigh/zkp-service/build/longfellow_build/testing/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/util/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/algebra/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/arrays/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/merkle/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/ligero/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/proto/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/random/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/sumcheck/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/gf2k/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/cbor/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/ec/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/zk/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/anoncred/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/base64/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/cbor_parser/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/compiler/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/ecdsa/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/jwt/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/logic/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/mac/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/mdoc/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/sha/cmake_install.cmake")
  include("/home/keleigh/zkp-service/build/longfellow_build/circuits/sha3/cmake_install.cmake")

endif()


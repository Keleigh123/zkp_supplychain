cmake_minimum_required(VERSION 3.20)
project(zkp_service)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MONGOCXX REQUIRED libmongocxx)
pkg_check_modules(BSONCXX REQUIRED libbsoncxx)

# Crow
include_directories(${CMAKE_SOURCE_DIR}/crow)
include_directories(${CMAKE_SOURCE_DIR}/zkp)   # <-- add this here
include_directories(${MONGOCXX_INCLUDE_DIRS})
include_directories(${BSONCXX_INCLUDE_DIRS})
include_directories(
  /home/keleigh/longfellow-zk/lib
  /home/keleigh/longfellow-zk/lib/zk
  /home/keleigh/longfellow-zk/lib/ligero
  /home/keleigh/longfellow-zk/lib/merkle
  /home/keleigh/longfellow-zk/lib/circuits/compiler
  /home/keleigh/longfellow-zk/lib/circuits/logic
    /home/keleigh/longfellow-zk/lib/sumcheck
       ${CMAKE_SOURCE_DIR}/zkp
)

# Longfellow-ZK (THIS is the correct root)
add_subdirectory(
    /home/keleigh/longfellow-zk/lib
    longfellow_build
)

# Aggregate Longfellow OBJECT libraries into a real static library
add_library(longfellow_static STATIC
    $<TARGET_OBJECTS:util>
    $<TARGET_OBJECTS:algebra>
    $<TARGET_OBJECTS:ec>
    $<TARGET_OBJECTS:flatsha>
    $<TARGET_OBJECTS:sha3>
    $<TARGET_OBJECTS:base64>
    $<TARGET_OBJECTS:mdoc>
)

# Libraries required by Longfellow object code
target_link_libraries(longfellow_static
    PUBLIC
        crypto
        zstd
)

add_executable(zkp_service
    main.cpp
    crypto/issuance.cpp
    zkp/prover.cpp
    zkp/verifier.cpp
    zkp/mode2_circuit.cpp
    zkp/circuits/mode2_circuit_internal.cpp
)

target_link_libraries(
    zkp_service
    PRIVATE
        longfellow_static
        ${MONGOCXX_LIBRARIES}
        ${BSONCXX_LIBRARIES}
        pthread
        sodium
)






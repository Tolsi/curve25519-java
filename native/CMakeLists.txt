cmake_minimum_required(VERSION 3.9)
project(curve25519 VERSION 0.5.0 DESCRIPTION "Curve25519")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(curve25519-donna STATIC curve25519-donna.c)

add_library(curve25519-ref10 STATIC)

target_include_directories(curve25519-ref10 PUBLIC
    ed25519/nacl_includes
    ed25519/additions
    ed25519/additions/generalized
    ed25519/tests
    ed25519/sha512
    ed25519
)

file(GLOB curve25519-ref10-files
    ed25519/*.c
    ed25519/additions/*.c
    ed25519/additions/generalized/*.c
    ed25519/nacl_sha512/*.c
    ed25519/tests/internal_fast_tests.c
)

target_sources(curve25519-ref10 PUBLIC ${curve25519-ref10-files})

add_library(curve25519 SHARED curve25519.c)

target_link_libraries(curve25519 curve25519-ref10 curve25519-donna)

target_include_directories(curve25519 PUBLIC
    ed25519/additions
    ed25519/additions/generalized
    ed25519/tests
)

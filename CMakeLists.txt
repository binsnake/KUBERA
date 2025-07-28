cmake_minimum_required(VERSION 3.10)
project(KUBERA LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kubera.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/virtual_memory.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/arithmetic.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/bit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/bitwise_logical.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/cmov.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/compare.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/control_flow.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/data.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/floating_80.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/floating_point.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/helpers.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/misc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/set.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/simd.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/stack_frame.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/string.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/syscall.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/system.cpp
)

message(STATUS "Found sources: ${SOURCES}")

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/boost_multiprecision/include
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/boost_config/include
)
target_compile_definitions(${PROJECT_NAME} PUBLIC BOOST_MP_STANDALONE)

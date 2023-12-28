cmake_minimum_required(VERSION 3.26)
project(AlpcKm)

set(CMAKE_CXX_STANDARD 23)

include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)

wdk_add_driver(AlpcKmDriver
        src/main.cpp
        src/alpc/message/message.h
        src/alpc/alpc.cc
        src/alpc/alpc.h
        src/logger/logger.h
        src/utils/utils.cc
        src/utils/utils.h
)
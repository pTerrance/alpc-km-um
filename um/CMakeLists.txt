cmake_minimum_required(VERSION 3.26)
project(AlpcUm)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

include_directories("${PROJECT_SOURCE_DIR}/src")

include_directories(deps/spdlog/include)

add_executable(AlpcUm
        src/main.cpp
        src/alpc/alpc.h
        src/alpc/alpc.cc
        src/alpc/message/message.h
        src/memory/memory.cc
        src/memory/memory.h)

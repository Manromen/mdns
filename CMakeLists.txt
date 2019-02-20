cmake_minimum_required(VERSION 3.13)
project(mdnstest)

set(CMAKE_CXX_STANDARD 14)

add_executable(mdnstest mdns.c mdns.h main.cpp MDNSRequestPerformer.cpp MDNSRequestPerformer.hpp mdnstypes.hpp mdnstypes.cpp)
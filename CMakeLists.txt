cmake_minimum_required(VERSION 3.13)
project(mdnstest)

set(CMAKE_C_STANDARD 11)

add_executable(mdnstest mdns.c mdns.h)
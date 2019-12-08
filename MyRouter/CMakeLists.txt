cmake_minimum_required(VERSION 2.8)

add_executable(main main.cpp)
target_include_directories(main PRIVATE ../HAL/include)
target_link_libraries(main router_hal)
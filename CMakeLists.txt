cmake_minimum_required(VERSION 3.12)

project(SNMP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NETSNMP REQUIRED netsnmp)
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)

include_directories(
    ${NETSNMP_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${nlohmann_json_INCLUDE_DIRS}
)
include_directories(${NETSNMP_INCLUDE_DIRS})
link_directories(${NETSNMP_LIBRARY_DIRS})

add_executable(SNMP main.cpp)

target_link_libraries(SNMP ${NETSNMP_LIBRARIES})
target_link_libraries(
    SNMP
    ${NETSNMP_LIBRARIES}
    ${CURL_LIBRARIES}
    nlohmann_json::nlohmann_json
)

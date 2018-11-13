cmake_minimum_required(VERSION 3.4)
project(POCO_TEST)

set(CMAKE_CXX_STANDARD 11)
include_directories("include")

find_package (Threads)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(Poco REQUIRED COMPONENTS Net NetSSL Data JSON Crypto Foundation)
message(INFO, ${Poco_INCLUDE_DIRS})
message(INFO, ${Poco_LIBRARIES})


set(SOURCE_FILES main.cpp)
add_executable(POCO_TEST ${SOURCE_FILES})

target_link_libraries(POCO_TEST
    ${CMAKE_THREAD_LIBS_INIT}
    ${Poco_LIBRARIES}
    )
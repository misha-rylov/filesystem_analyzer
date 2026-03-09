cmake_minimum_required(VERSION 3.16)
project(filesystem_analyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(nlohmann_json QUIET)

add_executable(filesystem_analyzer
    src/main.cpp
    src/analyzer.cpp
    src/scanner.cpp
)

if(nlohmann_json_FOUND)
    target_compile_definitions(filesystem_analyzer PRIVATE HAVE_JSON)
    target_include_directories(filesystem_analyzer PRIVATE ${nlohmann_json_INCLUDE_DIRS})
endif()

target_include_directories(filesystem_analyzer PRIVATE include)

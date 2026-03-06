cmake_minimum_required(VERSION 3.15)
project(PDFMalwareScanner VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED yara)
pkg_check_modules(PODOFO REQUIRED libpodofo)

add_executable(pdf_scanner
    src/main.cpp
    src/pdf_scanner.cpp
    src/yara_wrapper.cpp
)

target_include_directories(pdf_scanner PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${YARA_INCLUDE_DIRS}
    ${PODOFO_INCLUDE_DIRS}
)

target_link_libraries(pdf_scanner PRIVATE
    ${YARA_LIBRARIES}
    ${PODOFO_LIBRARIES}
    ssl
    crypto
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pdf_scanner PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS pdf_scanner DESTINATION bin)
install(DIRECTORY rules/ DESTINATION share/pdf_scanner/rules)

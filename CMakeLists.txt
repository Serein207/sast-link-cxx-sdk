cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    add_compile_definitions(BOOST_ASIO_HAS_CO_AWAIT)
endif()

project(sast-link VERSION 0.1.0 LANGUAGES CXX)

if(NOT DEFINED BUILD_EXAMPLE)
    option(BUILD_EXAMPLE "Build example executables" OFF)
endif()

cmake_policy(SET CMP0167 NEW)

find_package(Boost REQUIRED COMPONENTS system url beast)
find_package(OpenSSL 3.0 REQUIRED)

add_subdirectory(src/Network)
add_subdirectory(src/Controller)

add_library(${PROJECT_NAME} src/lib.cc)

target_link_libraries(${PROJECT_NAME} PRIVATE controller server)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC include
)

if(BUILD_EXAMPLE_EXECUTABLE)
    add_subdirectory(example)
endif()

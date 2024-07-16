cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    add_compile_definitions(BOOST_ASIO_HAS_CO_AWAIT)
endif()

project(sast-link VERSION 0.1.0 LANGUAGES CXX)

find_package(spdlog REQUIRED)
find_package(Boost REQUIRED COMPONENTS system url beast)
find_package(OpenSSL 3.0 REQUIRED)

add_subdirectory(src/details)

if(DEFINED BUILD_EXAMPLE)
    add_subdirectory(example)
endif()

add_library(${PROJECT_NAME} src/lib.cc)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE sast-link_details)

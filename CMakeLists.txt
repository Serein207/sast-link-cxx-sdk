cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(sast-link VERSION 0.1.0 LANGUAGES CXX)

find_package(spdlog REQUIRED)
find_package(Boost REQUIRED COMPONENTS system url beast)
find_package(OpenSSL 3.0 REQUIRED)

set(BUILD_EXAMPLE BOOL "Build example")

if(BUILD_EXAMPLE STREQUAL "ON")
    message("Build example")
    add_subdirectory(example)
endif()

set(BUILD_SAST_LINK_SHARED BOOL "Build shared library" OFF)

set(LIB_TYPE STATIC)

if(BUILD_SAST_LINK_SHARED STREQUAL "ON")
    set(LIB_TYPE SHARED)
    message("Building SAST Link C++ SDK: shared library")
else()
    message("Building SAST Link C++ SDK: static library")
endif()

add_subdirectory(src/details)

add_library(${PROJECT_NAME} ${LIB_TYPE} src/lib.cc)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE sast-link_details)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} PRIVATE /EHsc /MTd /W2 /c)
    target_compile_definitions(${PROJECT_NAME} 
    PRIVATE 
        WIN_EXPORT 
        BOOST_ASIO_HAS_CO_AWAIT
    )
endif()

if(BUILD_SAST_LINK_SHARED STREQUAL "ON")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SAST_LINK_SHARED)
endif()

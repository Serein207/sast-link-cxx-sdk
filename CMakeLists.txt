cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(sast-link VERSION 1.4.2 LANGUAGES CXX)

find_package(spdlog REQUIRED)
find_package(Boost REQUIRED COMPONENTS system url beast)
find_package(OpenSSL 3.0 REQUIRED)

set(BUILD_EXAMPLE OFF CACHE BOOL "Build sast-link example")
set(BUILD_SAST_LINK_SHARED ON CACHE BOOL "Build sast-link shared library")

message("------------------sast-link-cxx-sdk------------------")
message("Build example: ${BUILD_EXAMPLE}")
message("Build shared library: ${BUILD_SAST_LINK_SHARED}")
message("-----------------------------------------------------")

if(BUILD_EXAMPLE)
    add_subdirectory(example)
endif()

set(LIB_TYPE STATIC)

if(BUILD_SAST_LINK_SHARED)
    set(LIB_TYPE SHARED)
endif()

add_subdirectory(src/details)

add_library(${PROJECT_NAME} ${LIB_TYPE} src/lib.cc include/sast_link.h)

include(GNUInstallDirs)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(${PROJECT_NAME} PRIVATE sast-link_details Boost::beast)

if(MSVC)
    target_compile_definitions(${PROJECT_NAME}
        PRIVATE
        WIN_EXPORT
    )
endif()

if(BUILD_SAST_LINK_SHARED)
    target_compile_definitions(${PROJECT_NAME} PRIVATE SAST_LINK_SHARED)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER include/sast_link.h
)

install(TARGETS ${PROJECT_NAME}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

<div align=center>
    <img width=64 src="link.png">
</div>

<h1 align=center>SAST Link C++ SDK</h1>

<p align="center">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgreen.svg">
    <img src="https://img.shields.io/badge/language-C%2B%2B20-orange.svg">
</p>

<p align=center>English | <a href="./README_zh.md">简体中文</a></p>

## Brief

[SAST Link](https://github.com/NJUPT-SAST/sast-link-backend) is a comprehensive personnel management system and OAuth designed to provide a secure and efficient way to manage and authorize access to your applications and services.

This project is the cross-platform SDK for SAST Link which written in C++. If you're interested in the frontend, please visit SAST Link [frontend](https://github.com/NJUPT-SAST/sast-link).

## Features

- C++20 coroutine support
- Cross platform

## Start

### Prerequisites

Compiler & Build Tools

- A compiler that supports C++20 or later
- CMake 3.15 or later

Dependencies

- [Boost.Beast](https://github.com/boostorg/beast)
- [Boost.Url](https://github.com/boostorg/url)
- [OpenSSL](https://github.com/openssl/openssl)

### Clone & Build

Clone the repository:

```shell
git clone https://github.com/NJUPT-SAST/sast-evento-desktop.git
```

Build the project:

```shell
cmake -B build
cmake --build build
```

> [!NOTE]
> 
> if you want to build the example, you can use the following command:
> 
> ```shell
> cmake -B build -DBUILD_EXAMPLE=ON
> cmake --build build
> ```

### Usage

CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(example VERSION 0.1.0 LANGUAGES CXX)

option(BUILD_SAST_LINK_SHARED ON) # default is ON 

add_subdirectory(sast-link-cxx-sdk)

add_executable(example main.cc)

target_link_libraries(example PRIVATE
    sast-link
)

if (WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:${PROJECT_NAME}> $<TARGET_FILE_DIR:${PROJECT_NAME}> COMMAND_EXPAND_LISTS)
endif()
```

main.cc

```cpp
#include <sast_link.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <iostream>

namespace net = boost::asio;

int main() {
    net::io_context ioc;
    net::co_spawn(
        ioc,
        []() -> net::awaitable<void> {
            auto result = co_await sast_link::login();
            if (result) {
                std::cout << "code: " << result.value() << '\n';
            } else {
                std::cerr << "Login failed: " << result.error() << '\n';
            }
        },
        net::detached);
    ioc.run();
}
```

## TODO List

- [x] async get code from sast link
- [x] add more reliable error handling
- [ ] add unit tests
- [ ] add more api support
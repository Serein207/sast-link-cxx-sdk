<div align=center>
    <img width=64 src="link.png">
</div>

<h1 align=center>SAST Link C++ SDK</h1>

<p align="center">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgreen.svg">
    <img src="https://img.shields.io/badge/language-C%2B%2B20-orange.svg">
</p>

<p align=center> <a href="./README.md">English</a> |简体中文</p>

## 简介

[SAST Link](https://github.com/NJUPT-SAST/sast-link-backend) 是一个综合人员管理系统和 OAuth，旨在提供一种安全高效的方式来管理和授权访问您的应用程序和服务。

此项目是使用 C++ 编写的跨平台 SAST Link SDK。如果您对前端感兴趣，请访问 SAST Link [frontend](https://github.com/NJUPT-SAST/sast-link).


## 特性

- C++20 协程
- 跨平台

## 开始

### 预设条件

编译和构建工具

- 支持C++20或更高版本的编译器
- CMake 3.15 或更高版本

依赖项

- [Boost.Beast](https://github.com/boostorg/beast)
- [Boost.Url](https://github.com/boostorg/url)
- [OpenSSL](https://github.com/openssl/openssl)

### 克隆和构建

克隆仓库：

```shell
git clone https://github.com/NJUPT-SAST/sast-evento-desktop.git
```

构建项目：

```shell
cmake -B build
cmake --build build
```

> [!NOTE]
> 
> 如果您想构建示例，请使用以下命令：
> 
> ```shell
> cmake -B build -DBUILD_EXAMPLE=ON
> cmake --build build
> ```

### 使用

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

- [x] 异步获得link返回的code
- [x] 添加更可靠的错误处理
- [ ] 添加单元测试
- [ ] 添加更多 API 支持

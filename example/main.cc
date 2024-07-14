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

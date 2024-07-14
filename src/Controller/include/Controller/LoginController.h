#pragma once

#include <Network/HttpServer.h>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core/string_type.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <memory>
#include <string>

class LoginController {
public:
    boost::asio::awaitable<void> begin_login_via_sast_link(std::string& auth_code);
    boost::asio::awaitable<void> stop_server();
    ~LoginController();

private:
    boost::asio::awaitable<void> setup_server(std::string& auth_code);

    std::unique_ptr<HttpServer> _login_redirect_server = nullptr;
    std::string _state;
    std::string _code_verifier;
};

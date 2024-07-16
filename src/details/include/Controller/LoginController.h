#pragma once

#include <Network/HttpServer.h>

namespace sast_link {

using code_t = std::string;

namespace details {

class LoginController {
public:
    boost::asio::awaitable<void> begin_login_via_sast_link(code_t& auth_code);
    boost::asio::awaitable<void> stop_server();
    ~LoginController();

private:
    boost::asio::awaitable<void> setup_server(code_t& auth_code);

    std::unique_ptr<HttpServer> _login_redirect_server = nullptr;
    std::string _state;
    std::string _code_verifier;
};

} // namespace details
} // namespace sast_link

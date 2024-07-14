#include "Controller/LoginController.h"
#include <sast_link.h>

namespace sast_link {

boost::asio::awaitable<Result<std::string>> login() {
    LoginController controller;
    std::string auth_code;
    try {
        co_await controller.begin_login_via_sast_link(auth_code);
        co_await controller.stop_server();
    } catch (const std::exception& e) {
        co_return Result<std::string>::Err(e.what());
    }
    co_return Result<std::string>::Ok(auth_code);
}

} // namespace sast_link

#include <Controller/LoginController.h>
#include <sast_link.h>

namespace net = boost::asio;

namespace sast_link {

net::awaitable<Result<code_t>> login() {
    details::LoginController controller;
    std::string auth_code;
    try {
        co_await controller.begin_login_via_sast_link(auth_code);
        co_await controller.stop_server();
    } catch (const std::exception& e) {
        co_return Result<code_t>::Err(e.what());
    }
    co_return Result<code_t>::Ok(auth_code);
}

} // namespace sast_link

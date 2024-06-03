#include <Controller/LoginController.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

namespace beast = boost::beast;
namespace net = boost::asio;
using tcp = net::ip::tcp;

int main() {
  boost::asio::io_context ioc;
  LoginController controller(ioc);
  net::co_spawn(ioc, controller.begin_login_via_sast_link(),
                boost::asio::detached);
  ioc.run();
}

#pragma once
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <functional>
#include <map>

namespace sast_link::details {

class HttpServer {
    using tcp = boost::asio::ip::tcp;
    using tcp_stream = typename boost::beast::tcp_stream::rebind_executor<
        boost::asio::use_awaitable_t<>::executor_with_default<boost::asio::any_io_executor>>::other;
    using path_t = std::string;
    using Callback = std::function<boost::beast::http::response<boost::beast::http::string_body>(
        boost::beast::http::request<boost::beast::http::string_body>)>;

public:
    void route(path_t const& path, Callback&& callback);
    boost::asio::awaitable<void> listen(std::string const& host, std::uint16_t port);
    boost::asio::awaitable<void> stop();

private:
    boost::asio::awaitable<void> do_session(tcp_stream stream);

    std::map<path_t, Callback> _route_map;
};

} // namespace sast_link::details
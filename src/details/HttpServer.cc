#include <Network/HttpServer.h>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http/impl/write.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/version.hpp>
#include <cassert>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

void HttpServer::route(path_t const& path, Callback&& callback) {
    assert(path.starts_with('/'));
    _route_map[path] = std::move(callback);
}

net::awaitable<void> HttpServer::listen(std::string const& host, std::uint16_t port) {
    auto endpoint = tcp::endpoint(net::ip::make_address(host), port);
    auto acceptor = net::use_awaitable_t<net::any_io_executor>::as_default_on(
        tcp::acceptor(co_await net::this_coro::executor));

    acceptor.open(endpoint.protocol());

    acceptor.set_option(net::socket_base::reuse_address(true));

    acceptor.bind(endpoint);

    acceptor.listen(net::socket_base::max_listen_connections);

    co_await do_session(tcp_stream(co_await acceptor.async_accept()));
}

net::awaitable<void> HttpServer::do_session(tcp_stream stream) {
    beast::flat_buffer buffer;

    try {
        using namespace std::chrono_literals;

        stream.expires_after(10s);

        http::request<http::string_body> request;
        co_await http::async_read(stream, buffer, request);

        // handle requst
        auto target = request.target();
        auto end_pos = target.find_first_of('?');
        auto route_path = target.substr(0, end_pos);

        if (auto it = _route_map.find(route_path); it != _route_map.end()) {
            auto res = it->second(request);
            res.keep_alive(request.keep_alive());
            res.prepare_payload();
            co_await http::async_write(stream, res, net::use_awaitable);
        } else {
            http::response<http::string_body> res{http::status::not_found, request.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.keep_alive(request.keep_alive());
            res.body() = "404 NOT FOUND";
            res.prepare_payload();
            co_await http::async_write(stream, res, net::use_awaitable);
        }

        stream.socket().shutdown(tcp::socket::shutdown_send);
        co_await stop();
    } catch (boost::system::system_error& se) {
        if (se.code() != http::error::end_of_stream)
            throw;
    }
}

net::awaitable<void> HttpServer::stop() {
    _route_map.clear();
    auto acceptor = net::use_awaitable_t<net::any_io_executor>::as_default_on(
        tcp::acceptor(co_await net::this_coro::executor));
    acceptor.close();
}

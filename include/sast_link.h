#pragma once
#include <boost/asio/awaitable.hpp>
#include <string>
#include <type_traits>

namespace sast_link {

template<typename T, typename E = std::string>
    requires std::is_convertible_v<E, std::string_view>
struct Result {
    enum class Status { Ok, Err } status;
    union {
        T ok;
        E err;
    };
};

boost::asio::awaitable<Result<std::string>> login();

} // namespace sast_link

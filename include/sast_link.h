#pragma once
#include <boost/asio/awaitable.hpp>
#include <stdexcept>
#include <string>
#include <utility>

#if defined(SAST_LINK_SHARED) && defined(WIN_EXPORT)
#define _SAST_LINK_EXPORTED __declspec(dllexport)
#elif defined(SAST_LINK_SHARED) && defined(_WIN32)
#define _SAST_LINK_EXPORTED __declspec(dllimport)
#else
#define _SAST_LINK_EXPORTED
#endif // SAST_LINK_SHARED

namespace sast_link {

using code_t = std::string;
using error_t = std::string; // error description

template<typename T, typename E = error_t>
class Result {
public:
    Result()
        : _status(State::Err)
        , _err() {}

    ~Result() {
        if (_status == State::Ok) {
            _ok.~T();
        } else {
            _err.~E();
        }
    }

    Result(T value)
        : _status(State::Ok)
        , _ok(std::move(value)) {}

    Result(Result&& rhs) noexcept {
        _status = rhs._status;
        if (_status == State::Ok) {
            new (&_ok) T(std::move(rhs._ok));
        } else {
            new (&_err) E(std::move(rhs._err));
        }
    }

    Result& operator=(Result&& rhs) noexcept {
        if (this == &rhs)
            return *this;
        this->~Result();
        _status = rhs._status;
        if (_status == State::Ok) {
            new (&_ok) T(std::move(rhs._ok));
        } else {
            new (&_err) E(std::move(rhs._err));
        }
        return *this;
    }

    template<typename... U>
    static Result Ok(U&&... value) {
        return Result(std::forward<decltype(value)>(value)...);
    }

    static Result Err(E e) {
        Result result;
        result._err = std::move(e);
        return result;
    }

    operator bool() const { return _status == State::Ok; }

    [[nodiscard]] const T& value() const& {
        if (_status == State::Ok) {
            return _ok;
        } else {
            throw std::runtime_error(_err);
        }
    }

    [[nodiscard]] T& value() & {
        if (_status == State::Ok) {
            return _ok;
        } else {
            throw std::runtime_error(_err);
        }
    }

    [[nodiscard]] T&& value() && {
        if (_status == State::Ok) {
            return std::move(_ok);
        } else {
            throw std::runtime_error(_err);
        }
    }

    [[nodiscard]] E error() const {
        if (_status == State::Err) {
            return _err;
        } else {
            throw std::runtime_error("Result is not an error");
        }
    }

private:
    enum class State { Ok, Err } _status;
    union {
        T _ok;
        E _err;
    };
};

_SAST_LINK_EXPORTED boost::asio::awaitable<Result<code_t>> login();

} // namespace sast_link

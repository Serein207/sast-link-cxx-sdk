#pragma once
#include <boost/asio/awaitable.hpp>
#include <string>

namespace sast_link {

using ErrMsg = std::string;

template<typename T>
struct Result {
    union {
        T ok;
        ErrMsg err;
    };

    Result()
        : _status(Status::Err)
        , err("Result is not initialized") {}

    explicit(false) Result(T const& value)
        : _status(Status::Ok)
        , ok(value) {}

    ~Result() noexcept {
        if (_status == Status::Ok) {
            ok.~T();
        } else {
            err.~ErrMsg();
        }
    }

    Result(Result&& rhs) noexcept {
        _status = rhs._status;
        if (_status == Status::Ok) {
            new (&ok) T(std::move(rhs.ok));
        } else {
            new (&err) ErrMsg(std::move(rhs.err));
        }
    }

    Result& operator=(Result&& rhs) noexcept {
        if (this == &rhs) {
            return *this;
        }
        this->~Result();
        _status = rhs._status;
        if (_status == Status::Ok) {
            new (&ok) T(std::move(rhs.ok));
        } else {
            new (&err) ErrMsg(std::move(rhs.err));
        }
        return *this;
    }

    template<typename... U>
    static Result Ok(U&&... value) {
        return Result<T>(std::forward<decltype(value)>(value)...);
    }

    static Result<T> Err(const ErrMsg& value) {
        Result result;
        result.value() = value;
        return result;
    }

    operator bool() const { return _status == Status::Ok; }

    [[nodiscard]] T&& value() {
        if (_status == Status::Ok) {
            return std::move(ok);
        } else {
            throw std::runtime_error(err);
        }
    }

    [[nodiscard]] const ErrMsg& error() const {
        if (_status == Status::Err) {
            return err;
        } else {
            throw std::runtime_error("Result is not an error");
        }
    }

private:
    enum class Status { Ok, Err } _status;
};

boost::asio::awaitable<Result<ErrMsg>> login();

} // namespace sast_link

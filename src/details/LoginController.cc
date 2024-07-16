#include <Controller/LoginController.h>
#include <fstream>
#include <boost/url.hpp>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>
#include <boost/algorithm/string.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace urls = boost::urls;

static constexpr std::string_view AUTH_SERVER_URL = "http://link.sast.fun/auth";
static constexpr std::string_view AUTH_CLIENT_ID = "381c34b9-14a4-4df9-a9db-40c2455be09f";

namespace sast_link {
namespace details {

static void open_url(std::string_view url) {
    using namespace std::string_literals;
    std::string url_str = "\""s + url.data() + "\"";
#ifdef __linux__
    system(("xdg-open "s + url_str).c_str());
#elif defined(_WIN32)
    system(("start \"\" "s + url_str).c_str());
#elif defined(_APPLE__)
    system(("open "s + url_str).c_str());
#else
    spdlog::error("unsurppoted os");
#endif
}

static std::string base64_encode(const unsigned char* input, size_t length) {
    BUF_MEM* buf_ptr = nullptr;
    auto b64 = BIO_new(BIO_f_base64());
    auto b_mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, b_mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, static_cast<int>(length));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &buf_ptr);

    std::string output(buf_ptr->data, buf_ptr->length);
    BIO_free_all(b64);
    return output;
}

static std::string gen_code_challenge_s256(std::string_view code_verifier) {
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, code_verifier.data(), code_verifier.size());
    EVP_DigestFinal_ex(ctx, sha256, nullptr);
    EVP_MD_CTX_free(ctx);

    std::string base64_encoded = base64_encode(sha256, SHA256_DIGEST_LENGTH);
    return base64_encoded;
}

boost::asio::awaitable<void> LoginController::begin_login_via_sast_link(code_t& auth_code) {
    co_await setup_server(auth_code);

    this->_state = "xyz";
    this->_code_verifier = "sast_forever";

    urls::url url(AUTH_SERVER_URL);
    url.params().append({{"client_id", AUTH_CLIENT_ID},
                         {"code_challenge", gen_code_challenge_s256(this->_code_verifier)},
                         {"code_challenge_method", "S256"},
                         {"redirect_uri", "http://localhost:1919/"},
                         {"response_type", "code"},
                         {"scope", "all"},
                         {"state", this->_state}});

    spdlog::info("URL: {}", url.data());
    open_url(url.data());
    co_await _login_redirect_server->listen("127.0.0.1", 1919);
}

net::awaitable<void> LoginController::setup_server(code_t& auth_code) {
    if (_login_redirect_server) {
        co_return;
    }
    _login_redirect_server = std::make_unique<HttpServer>();

    _login_redirect_server
        ->route("/", [this, &auth_code](const http::request<http::string_body> request) {
            // OAuth 2.0 Redirect Uri
            auto status_code = http::status::ok;
            std::string error_description;

            switch (request.method()) {
            case http::verb::get: {
                boost::urls::url_view url = request.target().substr(
                    request.target().find_first_of('?'));
                auto params = url.encoded_params();

                // check for state
                if (!params.contains("state")) {
                    status_code = http::status::bad_request;
                    error_description = "state is missing";
                    break;
                }
                auto state = params.find("state")->value.decode();
                if (state != this->_state) {
                    status_code = http::status::bad_request;
                    error_description = "state is invalid";
                    break;
                }
                // clear State, as it should be used only once
                this->_state.clear();

                // check for error
                if (params.contains("error")) {
                    error_description = params.contains("error_description")
                                            ? params.find("error_description")->value.decode()
                                            : params.find("error")->value.decode();
                    status_code = http::status::bad_request;
                    break;
                }

                // check for code
                if (params.contains("code")) {
                    std::string code = params.find("code")->value.decode();
                    auth_code = code;
                    spdlog::info("login succcess!");
                    spdlog::debug("Code: {}", code);
                    break;
                }

                status_code = http::status::bad_request;
                break;
            }
            case http::verb::options:
                break;
            default:
                status_code = http::status::bad_request;
                break;
            }

            http::response<http::string_body> res{status_code, request.version()};
            std::ifstream ifs;
            if (status_code == http::status::ok) {
                res = http::response<http::string_body>(http::status::ok,
                                                        request.version(),
                                                        "200 OK");
                res.set(http::field::content_type, "text/html");

                ifs.open(HTML_DIR "/ok.html", std::ios::in);
                if (ifs.is_open()) {
                    res.body() = std::string(std::istreambuf_iterator<char>(ifs),
                                             std::istreambuf_iterator<char>());
                } else {
                    spdlog::error("Error: file \"ok.html\" not exists");
                    res.body() = "OK";
                }
            } else {
                res = http::response<http::string_body>(status_code,
                                                        request.version(),
                                                        error_description);
                res.set(http::field::content_type, "text/html");
                ifs.open(HTML_DIR "/error.html", std::ios::in);
                if (ifs.is_open()) {
                    res.body() = std::string(std::istreambuf_iterator<char>(ifs),
                                             std::istreambuf_iterator<char>());
                    boost::replace_first(res.body(), "%1", error_description);
                } else {
                    spdlog::error("Error: file \"error.html\" not exists");
                    res.body() = "Error";
                }
            }
            ifs.close();

            res.set("Access-Control-Allow-Origin", "https://link.sast.fun");
            res.set("Access-Control-Allow-Methods", "GET, OPTIONS");
            res.set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization");
            return res;
        });
}

net::awaitable<void> LoginController::stop_server() {
    if (_login_redirect_server) {
        co_await _login_redirect_server->stop();
        _login_redirect_server.reset();
    }
    spdlog::info("server has stopped");
}

LoginController::~LoginController() = default;

} // namespace details
} // namespace sast_link

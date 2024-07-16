file(GLOB_RECURSE SOURCES "*.cc" "*.h")

add_library(sast-link_details ${LIB_TYPE} ${SOURCES})

target_include_directories(
    sast-link_details
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    sast-link_details
    PRIVATE
        spdlog::spdlog
        spdlog::spdlog
        Boost::system
        Boost::url
        Boost::beast
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_definitions(
    sast-link_details
    PRIVATE
        HTML_DIR="${CMAKE_CURRENT_SOURCE_DIR}/html"
)
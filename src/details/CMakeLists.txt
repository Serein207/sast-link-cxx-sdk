file(GLOB_RECURSE SOURCES "*.cc" "*.h")

if(WIN32)
    add_library(sast-link_details OBJECT ${SOURCES})
else()
    add_library(sast-link_details ${LIB_TYPE} ${SOURCES})
endif()

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

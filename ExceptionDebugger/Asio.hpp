#pragma once

#include <boost/asio.hpp>
#include <fmt/format.h>

/////////////
// Aliases //
/////////////

namespace asio = boost::asio;

namespace exdbg
{
	namespace ip = asio::ip;
	using ip::tcp;
	using asio::awaitable;
	using asio::co_spawn;
	using asio::detached;
	using asio::use_awaitable_t;
	namespace this_coro = asio::this_coro;

	using tcp_acceptor = use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
	using tcp_socket = use_awaitable_t<>::as_default_on_t<tcp::socket>;

	using high_resolution_timer = use_awaitable_t<>::as_default_on_t<asio::high_resolution_timer>;
}
	
////////////////
// Formatters //
////////////////

template <>
struct fmt::formatter<exdbg::tcp::endpoint> {
	template <typename ParseContext>
	constexpr auto parse(ParseContext& ctx) {
		return ctx.begin();
	}

	template <typename FormatContext>
	auto format(const exdbg::tcp::endpoint& endpoint, FormatContext& ctx) {
		return fmt::format_to(ctx.out(), "{}:{}", endpoint.address(), endpoint.port());
	}
};

template <>
struct fmt::formatter<exdbg::ip::address> {
	template <typename ParseContext>
	constexpr auto parse(ParseContext& ctx) {
		return ctx.begin();
	}

	template <typename FormatContext>
	auto format(const exdbg::ip::address& address, FormatContext& ctx) {
		return fmt::format_to(ctx.out(), "{}", address.to_string());
	}
};

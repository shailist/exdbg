#include <thread>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <regex>
#include <set>
#include <stdexcept>
#include "Asio.hpp"
#include "MessageQueue.hpp"

std::map<uint8_t*, size_t> protected_regions;
std::set<uint8_t*> breakpoints;

void add_breakpoint(uint8_t* breakpoint_address)
{
	MEMORY_BASIC_INFORMATION info{};
	if (0 == VirtualQuery(breakpoint_address, std::addressof(info), sizeof(info)))
	{
		throw std::runtime_error("VirtualQuery failed");
	}
	auto* region_base = static_cast<uint8_t*>(info.BaseAddress);

	++(protected_regions[region_base]);

	DWORD old_protect;
	if (!VirtualProtect(breakpoint_address, 1, info.Protect | PAGE_GUARD, std::addressof(old_protect)))
	{
		--(protected_regions[region_base]);
		if (0 == protected_regions.at(region_base))
		{
			protected_regions.erase(region_base);
		}
		throw std::runtime_error("VirtualProtect failed");
	}

	breakpoints.emplace(breakpoint_address);
}

void remove_breakpoint(uint8_t* breakpoint_address)
{
	if (!breakpoints.contains(breakpoint_address))
	{
		return;
	}

	breakpoints.erase(breakpoint_address);

	MEMORY_BASIC_INFORMATION info{};
	if (0 == VirtualQuery(breakpoint_address, std::addressof(info), sizeof(info)))
	{
		throw std::runtime_error("VirtualQuery failed");
	}
	auto* region_base = static_cast<uint8_t*>(info.BaseAddress);

	auto ref_count = --protected_regions.at(region_base);

	if (0 == ref_count)
	{
		protected_regions.erase(region_base);
		DWORD old_protect;
		if (!VirtualProtect(breakpoint_address, 1, info.Protect & ~PAGE_GUARD, std::addressof(old_protect)))
		{
			throw std::runtime_error("VirtualProtect failed");
		}
	}
}

enum class BreakpointResult
{
	None,
	Continue,
	Step
};

struct BreakpointHit
{
	DWORD thread_id;
	PEXCEPTION_POINTERS exception_info;
};

exdbg::MessageQueue<BreakpointHit> breakpoint_hits;
std::map<DWORD, exdbg::MessageQueue<BreakpointResult>> breakpoint_results;

thread_local uint8_t* single_step_address = nullptr;
thread_local BreakpointResult single_step_reason = BreakpointResult::None;

#pragma code_seg(".guard")

BreakpointResult yield_to_debugger(PEXCEPTION_POINTERS ExceptionInfo)
{
	auto* exception_address = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	std::cout << "Breakpoint hit: " << exception_address << std::endl;

	breakpoint_hits.push(BreakpointHit{ GetCurrentThreadId(), ExceptionInfo });
	
	return breakpoint_results[GetCurrentThreadId()].pop();
}

LONG veh_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
	auto* exception_address = static_cast<uint8_t*>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

	if (EXCEPTION_GUARD_PAGE == ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
		if (!breakpoints.contains(exception_address))
		{
			MEMORY_BASIC_INFORMATION info{};
			if (0 == VirtualQuery(exception_address, std::addressof(info), sizeof(info)))
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}
			auto* region_base = static_cast<uint8_t*>(info.BaseAddress);

			if (!protected_regions.contains(region_base))
			{
				// Page guard somewhere in the process, isn't relevant to us

				return EXCEPTION_CONTINUE_SEARCH;
			}

			// Trying to access an address protected by a PAGE_GUARD that we placed, but not a breakpoint.
			// Handling involves performing a single step, re-installing the PAGE_GUARD, and then continuing execution.

			single_step_reason = BreakpointResult::Continue;
		}
		else
		{
			// Trying to access an breakpointed address.
			// Resuming execution involves performing a single step, re-installing the PAGE_GUARD, and then
			// decide what to do base of whether we continue execution or just single step.

			single_step_reason = yield_to_debugger(ExceptionInfo);
		}

		single_step_address = exception_address;
		ExceptionInfo->ContextRecord->EFlags |= 0x100;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (EXCEPTION_SINGLE_STEP == ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
		// To continue execution, re-install the PAGE_GUARD on the address that the exception originated from

		MEMORY_BASIC_INFORMATION info{};
		if (0 == VirtualQuery(single_step_address, std::addressof(info), sizeof(info)))
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		DWORD old_protect;
		if (!VirtualProtect(single_step_address, 1, info.Protect | PAGE_GUARD, std::addressof(old_protect)))
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		if (BreakpointResult::None == single_step_reason)
		{
			// Single step that we didn't cause, just ignore it

			// Clear single step indicators
			single_step_address = nullptr;
			single_step_reason = BreakpointResult::None;

			return EXCEPTION_CONTINUE_SEARCH;
		}
		else if (BreakpointResult::Step == single_step_reason)
		{
			// The debugger performed a single step.
			// Resuming execution involves performing a single step, re-installing the PAGE_GUARD, and then
			// decide what to do base of whether we continue execution or just single step.

			single_step_reason = yield_to_debugger(ExceptionInfo);
			single_step_address = exception_address;
			ExceptionInfo->ContextRecord->EFlags |= 0x100;
		}
		
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
#pragma code_seg()

#include <range/v3/view/repeat_n.hpp>
#include <scn/scn.h>

namespace exdbg::gdb
{
	template <typename T>
	[[nodiscard]] std::string to_hex(const T& value);
    [[nodiscard]] std::string to_hex(const void* value, size_t size);
    
	template <typename T>
	[[nodiscard]] void from_hex(std::string_view& hex, T& value);
	[[nodiscard]] void from_hex(std::string_view& hex, void* value, size_t size);

	template <typename T>
	[[nodiscard]] std::string to_hex(const T& value)
	{
		return to_hex(std::addressof(value), sizeof(value));
	}

	template <typename T>
	[[nodiscard]] void from_hex(std::string_view& hex, T& value)
	{
		from_hex(hex, std::addressof(value), sizeof(value));
	}

	std::string to_hex(const void* value, size_t size)
	{
		std::string result;
		result.reserve(size * 2);

		const auto* begin = static_cast<const uint8_t*>(value);
		const auto* end = begin + size;
		for (auto* ptr = begin; end != ptr; ++ptr)
		{
			fmt::format_to(std::back_inserter(result), "{:02x}", *ptr);
		}

		return result;
	}

	void from_hex(std::string_view& hex, void* value, size_t size)
	{
		auto* begin = static_cast<uint8_t*>(value);
		auto* end = begin + size;
		auto* val_end = std::min(end, begin + ((hex.size() + 1) / 2));
		
		auto* ptr = begin;
		for (; val_end != ptr; ++ptr, hex = hex.substr(std::min(static_cast<size_t>(2), hex.size())))
		{
			int value;
			scn::scan(hex, "{:02x}", value);
			*ptr = static_cast<uint8_t>(value);
		}

		for (; end != ptr; ++ptr)
		{
			*ptr = 0;
		}
	}

    namespace x64Registers
    {
        std::string encode_context(const CONTEXT* context);
        std::string encode_context(const CONTEXT& context);
        
		void decode_context(std::string_view encoded_context, CONTEXT* target);
		void decode_context(std::string_view encoded_context, CONTEXT& target);

		template <typename T>
		void _encode_register(std::string& result, T& value);
        
		template <typename T>
        void _encode_unknown_register(std::string& result);
		
		template <typename T>
		void _decode_register(std::string_view& encoded_context, T& value);

		template <typename T>
		void _decode_unknown_register(std::string_view& encoded_context);
    }

	std::string x64Registers::encode_context(const CONTEXT* context)
	{
		return encode_context(*context);
	}

	std::string x64Registers::encode_context(const CONTEXT& context)
    {
        std::string result;
        
        _encode_register(result, context.Rax);
        _encode_register(result, context.Rbx);
        _encode_register(result, context.Rcx);
        _encode_register(result, context.Rdx);
        _encode_register(result, context.Rsi);
        _encode_register(result, context.Rdi);
        _encode_register(result, context.Rbp);
        _encode_register(result, context.Rsp);
        _encode_register(result, context.R8);
        _encode_register(result, context.R9);
        _encode_register(result, context.R10);
        _encode_register(result, context.R11);
        _encode_register(result, context.R12);
        _encode_register(result, context.R13);
        _encode_register(result, context.R14);
        _encode_register(result, context.R15);

        _encode_register(result, context.Rip);
        _encode_register(result, context.EFlags);

        DWORD cs = context.SegCs;
		DWORD ss = context.SegSs;
		DWORD ds = context.SegDs;
		DWORD es = context.SegEs;
		DWORD fs = context.SegFs;
		DWORD gs = context.SegGs;
        _encode_register(result, cs);
        _encode_register(result, ss);
        _encode_register(result, ds);
        _encode_register(result, es);
        _encode_register(result, fs);
        _encode_register(result, gs);

        _encode_unknown_register<BYTE[80]>(result); // floating_point_registers

        _encode_unknown_register<FLOAT>(result); // fctrl
        _encode_unknown_register<FLOAT>(result); // fstat
        _encode_unknown_register<FLOAT>(result); // ftag
        _encode_unknown_register<FLOAT>(result); // fiseg
        _encode_unknown_register<FLOAT>(result); // fioff
        _encode_unknown_register<FLOAT>(result); // foseg
        _encode_unknown_register<FLOAT>(result); // fooff
        _encode_unknown_register<FLOAT>(result); // fop

        _encode_register(result, context.Xmm0);
        _encode_register(result, context.Xmm1);
        _encode_register(result, context.Xmm2);
        _encode_register(result, context.Xmm3);
        _encode_register(result, context.Xmm4);
        _encode_register(result, context.Xmm6);
        _encode_register(result, context.Xmm5);
        _encode_register(result, context.Xmm7);
        _encode_register(result, context.Xmm8);
        _encode_register(result, context.Xmm9);
        _encode_register(result, context.Xmm10);
        _encode_register(result, context.Xmm11);
        _encode_register(result, context.Xmm12);
        _encode_register(result, context.Xmm13);
        _encode_register(result, context.Xmm14);
        _encode_register(result, context.Xmm15);
        _encode_register(result, context.MxCsr);

		return result;
    }

	void x64Registers::decode_context(std::string_view encoded_context, CONTEXT* target)
	{
		decode_context(std::move(encoded_context), *target);
	}

	void x64Registers::decode_context(std::string_view encoded_context, CONTEXT& target)
	{
		_decode_register(encoded_context, target.Rax);
		_decode_register(encoded_context, target.Rbx);
		_decode_register(encoded_context, target.Rcx);
		_decode_register(encoded_context, target.Rdx);
		_decode_register(encoded_context, target.Rsi);
		_decode_register(encoded_context, target.Rdi);
		_decode_register(encoded_context, target.Rbp);
		_decode_register(encoded_context, target.Rsp);
		_decode_register(encoded_context, target.R8);
		_decode_register(encoded_context, target.R9);
		_decode_register(encoded_context, target.R10);
		_decode_register(encoded_context, target.R11);
		_decode_register(encoded_context, target.R12);
		_decode_register(encoded_context, target.R13);
		_decode_register(encoded_context, target.R14);
		_decode_register(encoded_context, target.R15);

		_decode_register(encoded_context, target.Rip);
		_decode_register(encoded_context, target.EFlags);

		DWORD cs;
		DWORD ss;
		DWORD ds;
		DWORD es;
		DWORD fs;
		DWORD gs;
		_decode_register(encoded_context, cs);
		_decode_register(encoded_context, ss);
		_decode_register(encoded_context, ds);
		_decode_register(encoded_context, es);
		_decode_register(encoded_context, fs);
		_decode_register(encoded_context, gs);
		target.SegCs = static_cast<WORD>(cs);
		target.SegSs = static_cast<WORD>(ss);
		target.SegDs = static_cast<WORD>(ds);
		target.SegEs = static_cast<WORD>(es);
		target.SegFs = static_cast<WORD>(fs);
		target.SegGs = static_cast<WORD>(gs);

		_decode_unknown_register<BYTE[80]>(encoded_context); // floating_point_registers

		_decode_unknown_register<FLOAT>(encoded_context); // fctrl
		_decode_unknown_register<FLOAT>(encoded_context); // fstat
		_decode_unknown_register<FLOAT>(encoded_context); // ftag
		_decode_unknown_register<FLOAT>(encoded_context); // fiseg
		_decode_unknown_register<FLOAT>(encoded_context); // fioff
		_decode_unknown_register<FLOAT>(encoded_context); // foseg
		_decode_unknown_register<FLOAT>(encoded_context); // fooff
		_decode_unknown_register<FLOAT>(encoded_context); // fop

		_decode_register(encoded_context, target.Xmm0);
		_decode_register(encoded_context, target.Xmm1);
		_decode_register(encoded_context, target.Xmm2);
		_decode_register(encoded_context, target.Xmm3);
		_decode_register(encoded_context, target.Xmm4);
		_decode_register(encoded_context, target.Xmm6);
		_decode_register(encoded_context, target.Xmm5);
		_decode_register(encoded_context, target.Xmm7);
		_decode_register(encoded_context, target.Xmm8);
		_decode_register(encoded_context, target.Xmm9);
		_decode_register(encoded_context, target.Xmm10);
		_decode_register(encoded_context, target.Xmm11);
		_decode_register(encoded_context, target.Xmm12);
		_decode_register(encoded_context, target.Xmm13);
		_decode_register(encoded_context, target.Xmm14);
		_decode_register(encoded_context, target.Xmm15);
		_decode_register(encoded_context, target.MxCsr);
	}

	template <typename T>
	void x64Registers::_encode_register(std::string& result, T& value)
	{
		result += to_hex(value);
	}

	template <typename T>
	void x64Registers::_encode_unknown_register(std::string& result)
	{
		result.append_range(ranges::views::repeat_n('x', sizeof(T) * 2));
	}

	template<typename T>
	void x64Registers::_decode_register(std::string_view& encoded_context, T& value)
	{
		from_hex(encoded_context, value);
	}

	template<typename T>
	void x64Registers::_decode_unknown_register(std::string_view& encoded_context)
	{
		encoded_context = encoded_context.substr(sizeof(T) * 2);
	}
}

void go_away_hacker()
{
	std::cout << "Go away hacker..." << std::endl;
}

void test_breakpoint()
{
	std::cout << "hmmm..." << std::endl;
}

std::atomic<bool> finished = false;

void test_thread()
{
	auto* breakpoint_addr = reinterpret_cast<uint8_t*>(&test_breakpoint);
	if (*breakpoint_addr == 0xE9)
	{
		// Deref jump table
		breakpoint_addr = reinterpret_cast<uint8_t*>(breakpoint_addr + *reinterpret_cast<uint32_t*>(breakpoint_addr + 1) + 5);
	}

	while (true)
	{
		std::cout << std::endl;

		std::cout << "Options:" << std::endl;
		std::cout << "1. Breakpoint" << std::endl;

		if (breakpoints.contains(breakpoint_addr))
		{
			std::cout << "2. Uninstall breakpoint" << std::endl;
		}
		else
		{
			std::cout << "2. Install breakpoint" << std::endl;
		}

		std::cout << "3. Exit" << std::endl;
		std::cout << "Anything else: Nothing" << std::endl;

		std::cout << "Enter choice: ";

		std::string line;
		std::getline(std::cin, line);

		std::cout << std::endl;
	
		int choice;
		std::stringstream(line) >> choice;
		
		if (1 == choice)
		{
			test_breakpoint();
		}
		else if (2 == choice)
		{
			if (breakpoints.contains(breakpoint_addr))
			{
				remove_breakpoint(breakpoint_addr);
			}
			else
			{
				add_breakpoint(breakpoint_addr);
			}
		}
		else if (3 == choice)
		{
			finished = true;
			break;
		}
	}
}

namespace exdbg::gdb
{
	[[nodiscard]] uint8_t calculate_checksum(const std::string_view& data)
	{
		uint8_t checksum = 0;
		for (auto chr : data)
		{
			checksum += chr;
		}
		return checksum;
	}
	
	void dummy_thread_ep()
	{
		ExitThread(0);
	}

	enum class PacketType
	{
		None,

		Acknowlegment,
		Packet
	};

	struct Packet
	{
		PacketType type;
		std::vector<std::optional<std::string>> match;
	};

	class GdbServer
	{
	public:
		GdbServer() = default;

		awaitable<void> init(uint16_t port);
		[[nodiscard]] awaitable<BreakpointResult> handle_breakpoint(BreakpointHit breakpoint_hit, bool init = false);

	private:
		[[nodiscard]] awaitable<Packet> _get_packet();
		awaitable<void> _send_response(std::string response, bool include_ack = true);

		awaitable<void> _processes_packet();

		[[nodiscard]] static std::vector<std::optional<std::string>> _s_parse_match_parts(const std::smatch& match);
		[[nodiscard]] static size_t _s_get_readable_size(void* address, size_t max_size);

		///////////////////
		// Packets Types //
		///////////////////

		static constexpr auto* ACKNOWLEGMENT_REGEX = R"~~([+-])~~";
		awaitable<void> _handle_acknowlegment(std::vector<std::optional<std::string>> match);

		static constexpr auto* PACKET_REGEX = R"~~(\$([^#]*)#([0-9a-fA-F]{2}))~~";
		awaitable<void> _handle_packet(std::vector<std::optional<std::string>> match);

		/////////////
		// Packets //
		/////////////

		static constexpr auto* QUERY_SUPPORTED_FEATURES_REGEX = R"~~(qSupported:([a-zA-Z0-9+-:]+))~~";
		awaitable<void> _handle_query_supported_features(std::vector<std::optional<std::string>> match);

		static constexpr auto* QUERY_HALT_REASON_REGEX = R"~~(\?)~~";
		awaitable<void> _handle_query_halt_reason(std::vector<std::optional<std::string>> match);

		//static constexpr auto* QUERY_TRACE_STATUS_REGEX = R"~~(qTStatus)~~";
		//awaitable<void> _handle_query_trace_status(std::vector<std::optional<std::string>> match);

		static constexpr auto* GET_REGISTERS_REGEX = R"~~(g)~~";
		awaitable<void> _handle_get_registers(std::vector<std::optional<std::string>> match);

		static constexpr auto* SET_REGISTERS_REGEX = R"~~(G([0-9a-fA-FxX]+))~~";
		awaitable<void> _handle_set_registers(std::vector<std::optional<std::string>> match);

		static constexpr auto* READ_MEMORY_REGEX = R"~~(m([0-9a-fA-F]+),([0-9a-fA-F]+))~~";
		awaitable<void> _handle_read_memory(std::vector<std::optional<std::string>> match);

		static constexpr auto* WRITE_MEMORY_REGEX = R"~~([MX]([0-9a-fA-F]+),([0-9a-fA-F]+):([0-9a-fA-F]+))~~";
		awaitable<void> _handle_write_memory(std::vector<std::optional<std::string>> match);

		static constexpr auto* STEP_REGEX = R"~~(s([0-9a-fA-F]+)?)~~";
		awaitable<void> _handle_step(std::vector<std::optional<std::string>> match);

		static constexpr auto* CONTINUE_REGEX = R"~~(c([0-9a-fA-F]+)?)~~";
		awaitable<void> _handle_continue(std::vector<std::optional<std::string>> match);


	private:
		std::optional<tcp_socket> m_socket;
		std::string m_buffer;

		std::optional<BreakpointHit> m_breakpoint_hit;
		std::optional<BreakpointResult> m_breakpoint_result;
	};

	awaitable<void> GdbServer::init(uint16_t port)
	{
		auto executor = co_await this_coro::executor;

		tcp_acceptor acceptor(executor, tcp::endpoint(tcp::v4(), 4444));

		std::cout << "Listening on port 4444" << std::endl;
		m_socket = co_await acceptor.async_accept();

		m_buffer.clear();
		m_breakpoint_hit.reset();

		auto* breakpoint_addr = reinterpret_cast<uint8_t*>(&dummy_thread_ep);
		if (*breakpoint_addr == 0xE9)
		{
			// Deref jump table
			breakpoint_addr = reinterpret_cast<uint8_t*>(breakpoint_addr + *reinterpret_cast<uint32_t*>(breakpoint_addr + 1) + 5);
		}

		AddVectoredExceptionHandler(1, veh_handler);

		add_breakpoint(breakpoint_addr);

		{
			std::jthread dummy_thread(dummy_thread_ep);

			auto breakpoint_hit = breakpoint_hits.pop();
			auto result = co_await handle_breakpoint(breakpoint_hit, true);

			breakpoint_results[breakpoint_hit.thread_id].push(result);
		}

		remove_breakpoint(breakpoint_addr);
	}

	awaitable<BreakpointResult> GdbServer::handle_breakpoint(BreakpointHit breakpoint_hit, const bool init)
	{
		m_breakpoint_hit = breakpoint_hit;
		m_breakpoint_result.reset();

		if (!init)
		{
			co_await _send_response("S05");//, false);
		}

		while (!m_breakpoint_result.has_value())
		{
			co_await _processes_packet();
		}

		auto result = m_breakpoint_result.value();

		m_breakpoint_hit.reset();
		m_breakpoint_result.reset();

		co_return result;
	}

	awaitable<Packet> GdbServer::_get_packet()
	{
		static const auto acknowlegment_regex = std::regex(std::format("^{}", ACKNOWLEGMENT_REGEX));
		static const auto packet_regex = std::regex(std::format("^{}", PACKET_REGEX));

		while (true)
		{
			////////////////////////////////////////////////////
			// Check and return if there is a buffered packet //
			////////////////////////////////////////////////////

			std::smatch match;
			auto packet_type = PacketType::None;
			if (std::regex_search(m_buffer, match, acknowlegment_regex))
			{
				packet_type = PacketType::Acknowlegment;
			}
			else if (std::regex_search(m_buffer, match, packet_regex))
			{
				packet_type = PacketType::Packet;
			}

			if (PacketType::None != packet_type)
			{
				std::vector<std::optional<std::string>> match_parts = _s_parse_match_parts(match);
				m_buffer.erase(0, match_parts[0].value().size());
				co_return Packet{ packet_type, std::move(match_parts) };
			}

			//////////////////////////////////////
			// Receive and buffer incoming data //
			//////////////////////////////////////

			asio::streambuf temp;
			boost::asio::streambuf::mutable_buffers_type mutable_temp = temp.prepare(1024);
			auto temp_size = co_await m_socket->async_read_some(mutable_temp);
			temp.commit(temp_size);

			m_buffer += std::string((std::istreambuf_iterator<char>(&temp)), std::istreambuf_iterator<char>());
		}
	}

	awaitable<void> GdbServer::_send_response(std::string response, bool include_ack)
	{
		std::string packet = fmt::format("{}${}#{:02x}", include_ack ? "+" : "", std::move(response), calculate_checksum(response));

		std::cout << "-> " << packet << std::endl;
		co_await m_socket->send(asio::buffer(packet));
	}

	awaitable<void> GdbServer::_processes_packet()
	{
		auto packet = co_await _get_packet();
		auto& [type, match] = packet;
		std::cout << std::endl << "<- " << match[0].value() << std::endl;

		switch (type)
		{
		case PacketType::Acknowlegment:
			co_await _handle_acknowlegment(std::move(match));
			break;

		case PacketType::Packet:
			co_await _handle_packet(std::move(match));
			break;

		default:
			std::unreachable();
		}
	}

	std::vector<std::optional<std::string>> GdbServer::_s_parse_match_parts(const std::smatch& match)
	{
		std::vector<std::optional<std::string>> parts;
		parts.reserve(match.size());

		for (const auto& sub_match : match)
		{
			if (sub_match.matched)
			{
				parts.emplace_back(sub_match.str());
			}
			else
			{
				parts.emplace_back(std::nullopt);
			}
		}

		return parts;
	}

	size_t GdbServer::_s_get_readable_size(void* address, size_t max_size)
	{
		auto* begin = static_cast<uint8_t*>(address);
		auto* end = begin + max_size;
		
		auto* current = begin;
		for (; end != current; ++current)
		{
			__try
			{
				(void)*current;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				break;
			}
		}

		return static_cast<size_t>(current - begin);
	}

	awaitable<void> GdbServer::_handle_acknowlegment(std::vector<std::optional<std::string>> match)
	{
		//std::cout << "  Acknowlegment:     " << match[0] << std::endl;

		co_return;
	}

	awaitable<void> GdbServer::_handle_packet(std::vector<std::optional<std::string>> match)
	{
		static const auto query_supported_features_regex = std::regex(std::format("{}", QUERY_SUPPORTED_FEATURES_REGEX));
		static const auto query_halt_reason_regex = std::regex(std::format("{}", QUERY_HALT_REASON_REGEX));
		//static const auto query_trace_status_regex = std::regex(std::format("{}", QUERY_TRACE_STATUS_REGEX));
		static const auto get_registers_regex = std::regex(std::format("{}", GET_REGISTERS_REGEX));
		static const auto set_registers_regex = std::regex(std::format("{}", SET_REGISTERS_REGEX));
		static const auto read_memory_regex = std::regex(std::format("{}", READ_MEMORY_REGEX));
		static const auto write_memory_regex = std::regex(std::format("{}", WRITE_MEMORY_REGEX));
		static const auto step_regex = std::regex(std::format("{}", STEP_REGEX));
		static const auto continue_regex = std::regex(std::format("{}", CONTINUE_REGEX));

		//std::cout << "  Packet data:       " << match[1] << std::endl;
		//std::cout << "  Packet checksum:   " << match[2] << std::endl;

		const auto& packet_data = match[1].value();

		std::smatch command_match;
		if (std::regex_match(packet_data, command_match, query_supported_features_regex))
		{
			co_await _handle_query_supported_features(_s_parse_match_parts(command_match));
		}
		else if (std::regex_match(packet_data, command_match, query_halt_reason_regex))
		{
			co_await _handle_query_halt_reason(_s_parse_match_parts(command_match));
		}
		//else if (std::regex_match(packet_data, command_match, query_trace_status_regex))
		//{
		//	co_await _handle_query_trace_status(_s_parse_match_parts(command_match));
		//}
		else if (std::regex_match(packet_data, command_match, get_registers_regex))
		{
			co_await _handle_get_registers(_s_parse_match_parts(command_match));
		}
		else if (std::regex_match(packet_data, command_match, set_registers_regex))
		{
			co_await _handle_set_registers(_s_parse_match_parts(command_match));
		}
		else if (std::regex_match(packet_data, command_match, read_memory_regex))
		{
			co_await _handle_read_memory(_s_parse_match_parts(command_match));
		}
		else if (std::regex_match(packet_data, command_match, write_memory_regex))
		{
			co_await _handle_write_memory(_s_parse_match_parts(command_match));
		}
		else if (std::regex_match(packet_data, command_match, step_regex))
		{
			co_await _handle_step(_s_parse_match_parts(command_match));
		}
		else if (std::regex_match(packet_data, command_match, continue_regex))
		{
			co_await _handle_continue(_s_parse_match_parts(command_match));
		}
		else
		{
			std::cout << "Unhandled command: " << packet_data << std::endl;
			co_await _send_response("");
		}
	}

	awaitable<void> GdbServer::_handle_query_supported_features(std::vector<std::optional<std::string>> match)
	{
		co_await _send_response("vContSupported-");
	}

	awaitable<void> GdbServer::_handle_query_halt_reason(std::vector<std::optional<std::string>> match)
	{
		co_await _send_response("S05");
	}

	//awaitable<void> GdbServer::_handle_query_trace_status(std::vector<std::optional<std::string>> match)
	//{
	//	if (m_breakpoint_hit)
	//	{
	//		co_await _send_response("T0;tstop:breakpoint:0");
	//	}
	//	else
	//	{
	//		co_await _send_response("T1");
	//	}
	//}

	awaitable<void> GdbServer::_handle_get_registers(std::vector<std::optional<std::string>> match)
	{
		if (m_breakpoint_hit)
		{
			std::string encoded_context = x64Registers::encode_context(m_breakpoint_hit->exception_info->ContextRecord);
			
			co_await _send_response(std::move(encoded_context));
		}
	}

	awaitable<void> GdbServer::_handle_set_registers(std::vector<std::optional<std::string>> match)
	{
		if (m_breakpoint_hit)
		{
			x64Registers::decode_context(match[1].value(), m_breakpoint_hit->exception_info->ContextRecord);

			co_await _send_response("OK");
		}
	}

	awaitable<void> GdbServer::_handle_read_memory(std::vector<std::optional<std::string>> match)
	{
		if (m_breakpoint_hit)
		{
			void* address;
			scn::scan(match[1].value(), "{:x}", reinterpret_cast<size_t&>(address));
			//std::string_view address_hex = match[1].value();
			//from_hex(address_hex, address);

			size_t size;
			std::string_view size_hex = match[2].value();
			from_hex(size_hex, size);

			size_t readable_size = _s_get_readable_size(address, size);

			co_await _send_response(to_hex(address, readable_size));
		}
	}

	awaitable<void> GdbServer::_handle_write_memory(std::vector<std::optional<std::string>> match)
	{
		if (m_breakpoint_hit)
		{
			void* address;
			scn::scan(match[1].value(), "{:x}", reinterpret_cast<size_t&>(address));
			//std::string_view address_hex = match[1].value();
			//from_hex(address_hex, address);

			size_t size;
			std::string_view size_hex = match[2].value();
			from_hex(size_hex, size);

			std::string_view data_hex = match[3].value();
			from_hex(data_hex, address, size);

			co_await _send_response(to_hex(address, size));
		}
	}

	awaitable<void> GdbServer::_handle_step(std::vector<std::optional<std::string>> match)
	{
		m_breakpoint_result = BreakpointResult::Step;
		
		if (match[1].has_value())
		{
			void* address;
			std::string_view address_hex = match[1].value();
			from_hex(address_hex, address);

			m_breakpoint_hit->exception_info->ContextRecord->Rip = reinterpret_cast<DWORD64>(address);
		}

		co_await _send_response("OK");
	}

	awaitable<void> GdbServer::_handle_continue(std::vector<std::optional<std::string>> match)
	{
		m_breakpoint_result = BreakpointResult::Continue;
		
		if (match[1].has_value())
		{
			void* address;
			std::string_view address_hex = match[1].value();
			from_hex(address_hex, address);

			m_breakpoint_hit->exception_info->ContextRecord->Rip = reinterpret_cast<DWORD64>(address);
		}

		co_await _send_response("OK");
	}

	//awaitable<void> run()
	//{
	//	AddVectoredExceptionHandler(1, veh_handler);
	//	
	//	std::jthread thread(test_thread);
	//	
	//	std::cout << "[main] Waiting for breakpoint hits..." << std::endl;
	//	
	//	while (!finished)
	//	{
	//		BreakpointHit breakpoint_hit;
	//	
	//		try
	//		{
	//			breakpoint_hit = breakpoint_hits.pop(std::chrono::seconds(1));
	//		}
	//		catch (const exdbg::timeout_exception&)
	//		{
	//			continue;
	//		}
	//	
	//		std::cout << "[main] Breakpoint Rip: " << reinterpret_cast<void*>(breakpoint_hit.exception_info->ContextRecord->Rip) << std::endl;
	//		breakpoint_results[breakpoint_hit.thread_id].push(BreakpointResult::Continue);
	//	}
	//	
	//	std::cout << "[main] Waiting for thread to finish..." << std::endl;
	//}

	awaitable<void> co_main()
	{
		auto executor = co_await this_coro::executor;

		try
		{
			GdbServer server;
			co_await server.init(4444);

			std::jthread thread(test_thread);

			while (true)
			{
				auto breakpoint_hit = breakpoint_hits.pop();
				auto breakpoint_result = co_await server.handle_breakpoint(breakpoint_hit);
				breakpoint_results[breakpoint_hit.thread_id].push(breakpoint_result);
			}
		}
		catch (const std::runtime_error& error)
		{
			std::cout << "Error: " << error.what() << std::endl;
		}
		catch (const std::exception& exception)
		{
			std::cout << "Exception: " << exception.what() << std::endl;
		}
		catch (...)
		{
			std::cout << "Unknown error" << std::endl;
		}
	}

	void main()
	{
		asio::io_context io_context;

		asio::signal_set signals(io_context, SIGINT, SIGTERM);
		signals.async_wait([&](auto, auto) { io_context.stop(); });

		co_spawn(
			io_context,
			[&]() -> awaitable<void> {
				co_await co_main();
				io_context.stop();
			},
			detached
		);

		io_context.run();
	}
	

}

int main()
{
	exdbg::gdb::main();
	return 0;
}

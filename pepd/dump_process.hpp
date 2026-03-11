#pragma once

// content
#include "pe_header.hpp"
#include "pe_hash_database.hpp"
#include "windows.h"
#include <tlhelp32.h>
#include "simple.hpp"
#include "module_list.hpp"
#include "export_list.hpp"
#include "hash.h"
#include <set>
#include "terminate_monitor_hook.hpp"

constexpr std::size_t PAGE_SIZE = 0x1000;
constexpr std::size_t CODECHUNK_HEADER_HASH_SIZE = 0x200; // First X bytes are CRC32'd of each loose code chunk. Only unique CRC32s are processed deeply.
constexpr std::size_t CODECHUNK_NEW_HASH_LIMIT = 500; // At most X code chunks processed deeply per process

using namespace std;

struct MBI_BASIC_INFO
{
	std::uintptr_t base{};
	std::uintptr_t end{};
	DWORD protect{};
	bool valid{};
	bool executable{};
};

class dump_process
{
private:
	pe_hash_database* _db_clean{};
	bool _opened{};
	HANDLE _ph{};
	DWORD _pid{};
	std::string _process_name;
	export_list _export_list;
	bool _export_list_built{};
	PEPD_OPTIONS* _options{};
	std::unique_ptr<terminate_monitor_hook> _term_hook;

	std::uintptr_t _address_main_module{};

	bool _loaded_is64{};
	bool _is64{};
	bool _quieter{}; // Suppress some of the error and warning messages

	[[nodiscard]] MBI_BASIC_INFO get_mbi_info(std::uintptr_t address) const;
	[[nodiscard]] bool build_export_list_for_module(export_list& result, std::string_view library, const module_list& modules) const;

public:
	explicit dump_process(DWORD pid, pe_hash_database* db, PEPD_OPTIONS* options, bool quieter) noexcept;

	~dump_process();
	dump_process(const dump_process&) = delete;
	dump_process& operator=(const dump_process&) = delete;
	dump_process(dump_process&&) noexcept = default;
	dump_process& operator=(dump_process&&) noexcept = default;

	void dump_all();
	void dump_region(std::uintptr_t base);
	void dump_header(pe_header* header, std::uintptr_t base, DWORD pid);

	[[nodiscard]] DWORD get_pid() const noexcept { return _pid; }
	[[nodiscard]] bool build_export_list();
	[[nodiscard]] bool build_export_list(export_list* result, const char* library, module_list* modules);
	[[nodiscard]] int get_all_hashes(
		std::unordered_set<std::uint64_t>* output_hashes,
		std::unordered_set<std::uint64_t>* output_hashes_eps,
		std::unordered_set<std::uint64_t>* output_hashes_ep_shorts);
	[[nodiscard]] std::uint64_t hash_codechunk_header(std::uintptr_t base) const;
	[[nodiscard]] bool is64();
	[[nodiscard]] std::string_view get_process_name() const noexcept { return _process_name; };

	// Functions for dumping processes as they close
	[[nodiscard]] bool monitor_close_start(); // start terminate hooks
	[[nodiscard]] bool monitor_close_is_waiting() const; // check if the process has closed and is waiting dumping
	[[nodiscard]] bool monitor_close_dump_and_resume(); // dumps the process if it is waiting dumping
	[[nodiscard]] bool monitor_close_stop(); // stop terminate hooks
};

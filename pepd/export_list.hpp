#pragma once

#include <Windows.h>
#undef max()
#undef min()
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <string_view>
#include <span>
#include <algorithm>
#include <limits>
#include "utils.hpp"

class export_entry
{
public:
	std::string library_name;
    std::string name;
    WORD ord;
    bool is64;
    uint64_t rva;
    uint64_t address;

	export_entry(std::string_view library_name, std::string_view name, WORD ord, 
                 uint64_t rva, uint64_t address, bool is64);
    export_entry(const export_entry& other);
    export_entry(export_entry&& other) noexcept = default;
    export_entry& operator=(const export_entry& other) = delete;
    export_entry& operator=(export_entry&& other) noexcept = delete;
    ~export_entry() = default;
};

class export_list
{
private:
	uint64_t _min64{std::numeric_limits<uint64_t>::max()};
    uint64_t _max64{0};
    uint32_t _min32{std::numeric_limits<uint32_t>::max()};
    uint32_t _max32{0};
    uint32_t _bits32{0};
    uint64_t _bits64{0};

	std::unordered_map<uint64_t, std::unique_ptr<export_entry>> _address_to_exports; // List of export addresses in this export list
	std::unordered_set<uint64_t> _addresses;; // List of export addresses

public:
	export_list() = default;

    ~export_list() = default;
	export_list(const export_list&) = delete;
    export_list& operator=(const export_list&) = delete;
	export_list(export_list&&) noexcept = default;
    export_list& operator=(export_list&&) noexcept = default;
	
	bool add_exports(std::span<const std::byte> image, uint64_t image_base, 
                     const IMAGE_EXPORT_DIRECTORY* export_directory, bool is64);
    bool add_exports(const export_list& other);
    void add_export(uint64_t address, const export_entry& entry);

	// Find export addresses in a process
	[[nodiscard]] uint64_t find_export(std::string_view library, 
                                       std::string_view name, bool is64) const;
    [[nodiscard]] bool contains(uint64_t address) const;
    [[nodiscard]] bool contains(uint32_t address) const;

    // Functions to get quick filter values before doing a lookup
    [[nodiscard]] const export_entry* find(uint64_t address) const;

	[[nodiscard]] uint64_t get_min64() const noexcept { return _min64; }
    [[nodiscard]] uint64_t get_max64() const noexcept { return _max64; }
    [[nodiscard]] uint32_t get_min32() const noexcept { return _min32; }
    [[nodiscard]] uint32_t get_max32() const noexcept { return _max32; }
    [[nodiscard]] uint32_t get_nobits32() const noexcept { return ~_bits32; }
    [[nodiscard]] uint64_t get_nobits64() const noexcept { return ~_bits64; }
};

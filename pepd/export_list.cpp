#include "export_list.hpp"
#include <print>

// Safe read function
template<typename T>
[[nodiscard]] static bool sread(std::span<const std::byte> image, uintptr_t offset, T& value)
{
	if (offset + sizeof(T) > image.size())
		return false;
	std::memcpy(&value, image.data() + offset, sizeof(T));
	return true;
}

// Get string from image function
[[nodiscard]] static std::string sgets(std::span<const std::byte> image, uintptr_t offset,
									   size_t max_length = 511)
{
	if (offset >= image.size())
		return {};

	const auto* start = reinterpret_cast<const char*>(image.data() + offset);
	const auto* end = std::find(start, reinterpret_cast<const char*>(image.data() + image.size()), '\0');
	auto length = std::min(static_cast<size_t>(end - start), max_length);

	return std::string(start, length);
}

export_entry::export_entry(std::string_view library_name, std::string_view name, WORD ord,
                          uint64_t rva, uint64_t address, bool is64)
    : library_name(library_name)
    , name(name)
    , ord(ord)
    , is64(is64)
    , rva(rva)
    , address(address)
{
}

export_entry::export_entry(const export_entry& other)
    : library_name(other.library_name)
    , name(other.name)
    , ord(other.ord)
    , is64(other.is64)
    , rva(other.rva)
    , address(other.address)
{
}

bool export_list::contains(uint64_t address) const
{
	// Look up a 64-bit value
	if ( address <= std::numeric_limits<uint32_t>::max() )
		return contains(static_cast<uint32_t>(address));
	
	if (address > _max64 || address < _min64 || (address & ~_bits64) != 0)
	{
		// We know there is no match by this quick filtering. This improves performance hugely.
		return false;
	}

	// Lookup the address
	return _addresses.contains(address);
}

bool export_list::contains(uint32_t address) const
{
	// Look up a 32-bit value
	if (address > _max32 || address < _min32 || (address & ~_bits32) > 0)
	{
		// We know there is no match by this quick filtering. This improves performance hugely.
		return false;
	}

	// Lookup the address
	return _addresses.contains(address);
}

uint64_t export_list::find_export(std::string_view library, std::string_view name, bool is64) const
{
	// Find the specified procedure in the corresponding library. Limit it to the specific 32-bit or 64-bit version of the library.
	for (const auto& [addr, entry] : _address_to_exports)
	{
		if (entry->is64 == is64 &&
			(library.empty() || _stricmp(library.data(), entry->library_name.c_str()) == 0) &&
			_stricmp(name.data(), entry->name.c_str()) == 0)
		{
			// Found match
			return entry->address;
		}
	}

	// No match
	return 0;
}

const export_entry* export_list::find(uint64_t address) const
{
	// Lookup the address
	auto it = _address_to_exports.find(address);
	return (it != _address_to_exports.end()) ? it->second.get() : nullptr;
}

void export_list::add_export(uint64_t address, const export_entry& entry)
{
	// Register this export address for quick lookups later
	if (!_address_to_exports.contains(address))
	{
		auto new_entry = std::make_unique<export_entry>(entry);
		_address_to_exports.emplace(address, std::move(new_entry));

		if (_addresses.insert(address).second)
		{
			// Update our quick-lookup values
			if ( address > std::numeric_limits<uint32_t>::max() )
			{
				// 64bit value
				_max64 = std::max(_max64, address);
				_min64 = std::min(_max64, address);
				_bits64 |= address;
			}
			else
			{
				// 32bit value
				_max32 = std::max(_max32, static_cast<uint32_t>(address));
				_min32 = std::min(_min32, static_cast<uint32_t>(address));
				_bits32 |= static_cast<uint32_t>(address);
			}
		}
	}
}

bool export_list::add_exports(const export_list& other)
{
	// Merge the exports from the other list with the current export list
	for (const auto& [addr, entry] : other._address_to_exports)
		add_export(addr, *entry);
	return true;
}

bool export_list::add_exports(std::span<const std::byte> image, std::uint64_t image_base,
                              const IMAGE_EXPORT_DIRECTORY* export_directory, bool is64)
{
	if (!export_directory || export_directory->NumberOfFunctions = 0 ||
		export_directory->AddressOfNameOrdinals == 0)
	{
		return false;
	}

	// Get library name
	std::string library_name;
	if (export_directory->Name < image.size())
		library_name = sgets(image, export_directory->Name);

	if (library_name.empty())
	{
		// Library name is invalid, no point in continuing
		std::println(stderr,
			"WARNING: Invalid library export directory module name. "
            "Unable to add exports to table for import reconstruction. "
            "Library base 0x{:X}.", image_base);
		return false;
	}

	// Parse the export directory
	for (DWORD i = 0; i < export_directory->NumberOfNames; ++i)
	{
		// Load the ordinal
		WORD ordinal_relative = 0;
		uintptr_t ord_offset = export_directory->AddressOfNameOrdinals + i*sizeof(WORD);
		if (!sread(image, ord_offset, ordinal_relative))
			continue;

		DWORD ordinal = export_directory->Name + ordinal_relative;

		// Load the name RVA
		DWORD name_rva = 0;
		uintptr_t name_offset = export_directory->AddressOfNames + i*sizeof(DWORD);
		if (!sread(image, name_offset, name_rva))
			continue;

		// Get the name string
		std::string func_name;
		if (name_rva < image.size())
			func_name = sgets(image, name_rva);

		// Load the function RVA
		DWORD func_rva = 0;
		uintptr_t func_offset = export_directory->AddressOfFunctions + ordinal_relative * sizeof(DWORD);
		if (!sread(image, func_offset, func_rva))
			continue;

		// Don't consider RVAs that are multiples of 0x1000 to prevent mistakes
		if (func_rva % 0x1000 != 0)
		{
			uint64_t address = image_base + func_rva;

			// Add this export
			add_export(address, export_entry(library_name, func_name,
											 static_cast<WORD>(ordinal),
											 func_rva, address, is64));
		}
	}

	return true;
}

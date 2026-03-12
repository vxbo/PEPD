#define NOMINMAX
#include "dump_process.hpp"
#include <ranges>
#include <print>

namespace views = std::views;

static std::string narrow_module_name(const wchar_t* name)
{
	int result;
	if (!name || name[0] == '\0')
		goto ret;

	char buffer[MAX_PATH];
	result = WideCharToMultiByte(CP_UTF8, 0, name, -1, buffer, sizeof(buffer), nullptr, nullptr);

	if (result > 0)
		return std::string(buffer, static_cast<size_t>(result - 1));

ret:
	return "unknown";
}

dump_process::dump_process(DWORD pid, pe_hash_database* db, PEPD_OPTIONS* options, bool quieter) noexcept
	: _db_clean(db)
	, _pid(pid)
	, _options(options)
	, _quieter(_quieter && !_options->Verbose)
{
	// Dump this specified PID into the current directory
	_ph = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!_ph)
	{
		// try opening with minimal permissions. This works for most actions (except terminate hooking)
		_ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (_ph && _options->Verbose)
			std::println(stderr, "WARNING: For PID 0x{:x}, opened with fewer permissions.", pid);
	}

	//if (!_ph)
	//{
	//	if (!_quieter)
	//		std::println(stderr, "Failed to open process with PID 0x{:x}", pid);
	//	return;
	//}

	if( _ph )
	{
		_opened = true;

		// Try to load the main module name
		HANDLE hSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if(hSnapshot != INVALID_HANDLE_VALUE )
		{
			_opened = true;

			// Load the main module name
			MODULEENTRY32 tmpModule{ .dwSize = sizeof(MODULEENTRY32) };
			if( Module32First(hSnapshot, &tmpModule) )
			{
				_process_name = narrow_module_name(tmpModule.szModule);

				// Replace all '.'s in filename with underscores
				for (char& c : _process_name)
					if (c == '.') c = '_';
				
				_address_main_module = reinterpret_cast<std::uintptr_t>(tmpModule.modBaseAddr);
			}

			CloseHandle(hSnapshot);
		}

		if (_process_name.empty())
		{
			if (!_quieter)
			{
				if (GetLastError() == 299)
				{
					std::println(stderr, "ERROR: Unable to snapshot process PID 0x{:x}. "
								 "This can be as a result of the process being a 64 bit process and this tool is "
								 "running as a 32 bit process, or the process may have not finished being created or already closed.", pid);
				}
			}

			_process_name = "unknown";
		}
	}
	else
	{
		if (!_quieter)
		{
			std::println(stderr, "Failed to open process with PID 0x{:x}:", pid);
		}
	}
}

bool dump_process::is64()
{
	if (!_loaded_is64)
	{
		// Look at the main module to determine if it is 64 or 32 bit
		auto modules = std::make_unique<module_list>(); // empty
		auto main_module = std::make_unique<pe_header>(_ph, reinterpret_cast<void*>(_address_main_module),
			modules.get(), _options);
		main_module->process_pe_header();
		_is64 = main_module->is_64();
		_loaded_is64 = true;
	}

	if (_loaded_is64)
		return _is64;
	
	// Failed. Assume 64 bit.
	std::println(stderr, "ERROR: For PID 0x{:x}, was unable to look at main module to determine 32 or 64 bit mode.", _pid);
	return true;
}

MBI_BASIC_INFO dump_process::get_mbi_info(std::uintptr_t address) const
{
	_MEMORY_BASIC_INFORMATION64 mbi{};
	MBI_BASIC_INFO result;

	// Load this heap information
	 SIZE_T blockSize = VirtualQueryEx(_ph, reinterpret_cast<LPCVOID>(address), 
		reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&mbi), sizeof(_MEMORY_BASIC_INFORMATION64));

	if (blockSize == sizeof(_MEMORY_BASIC_INFORMATION64))
	{
		result.base = static_cast<std::uintptr_t>(mbi.BaseAddress);
		result.end = static_cast<std::uintptr_t>(mbi.BaseAddress + mbi.RegionSize);
		result.protect = mbi.Protect;
		result.valid = (mbi.State != MEM_FREE) && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
		result.executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
			PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	}
	else if (blockSize == sizeof(_MEMORY_BASIC_INFORMATION32))
	{
		auto* mbi32 = reinterpret_cast<const _MEMORY_BASIC_INFORMATION32*>(&mbi);

		result.base = static_cast<std::uintptr_t>(mbi32->BaseAddress);
		result.end = static_cast<std::uintptr_t>(mbi32->BaseAddress + mbi32->RegionSize);
		result.protect = mbi32->Protect;
		result.valid = (mbi32->State != MEM_FREE) && !(mbi32->Protect & (PAGE_NOACCESS | PAGE_GUARD));
		result.executable = (mbi32->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
			PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	}

	return result;
}

int dump_process::get_all_hashes(
	std::unordered_set<std::uint64_t>* output_hashes,
	std::unordered_set<std::uint64_t>* output_hashes_eps,
	std::unordered_set<std::uint64_t>* output_hashes_ep_shorts)
{
	// Adds all the modules in the process to the output array
	if (!_ph)
		return false;

	if (!_options->DumpChunks || build_export_list()) // Only build export list if getting hashes for code chunks
	{
		// First build a list of the modules
		auto modules = std::make_unique<module_list>(_pid);

		// Set the max address of the target process
		constexpr std::uintptr_t maxAddress = std::numeric_limits<std::uintptr_t>::max();

		// Walk the process heaps
		std::uintptr_t address = 0;

		// First loop to build a list of executable heaps for later use in locating loose executable heaps not associated with any modules
		std::set<std::uintptr_t> executable_heaps;
		if (_options->DumpChunks)
		{
			while (address < maxAddress)
			{
				MBI_BASIC_INFO mbi_info = get_mbi_info(address);

				// Check if this is a loose executable heap
				if (mbi_info.base > 0 && mbi_info.end > 0 &&
					mbi_info.valid && mbi_info.executable)
				{
					executable_heaps.insert(mbi_info.base);
				}

				if (mbi_info.end + 1 <= address)
					break;
				address = mbi_info.end + 1;
			}
		}

		// Load all the PE files in the process
		address = 0;

		while (address < maxAddress)
		{
			MBI_BASIC_INFO mbi_info = get_mbi_info(address);

			if (mbi_info.base > 0 && mbi_info.end > 0 && mbi_info.valid)
			{
				if (_options->Verbose)
				{
					std::println("INFO: Scanning from region from 0x{:x} to 0x{:x} for MZ headers.", 
						mbi_info.base, mbi_info.end);
				}

				// This heap may have a PE file, check all page alignments for a "MZ".
				std::uintptr_t base = mbi_info.base - (mbi_info.base % PAGE_SIZE); // shouldn't be required.
				std::array<char, 2> output{};
				SIZE_T out_read {};
				int count = 0;

				while (base + 0x300 < mbi_info.end && count < 1000) // Skip the rest of the section if we have looped over 1000 pages.
				{
					if (ReadProcessMemory(_ph, reinterpret_cast<LPCVOID>(base), output.data(), 2, &out_read) && out_read == 2)
					{
						if (output[0] == 'M' && output[1] == 'Z')
						{
							if (_options->Verbose)
								std::println("INFO: Found MZ header at {:x}.", base);

							// Bingo, possible MZ file
							auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base), modules.get(), _options);

							header->process_pe_header();
							header->process_sections();

							if (header->somewhat_parsed())
							{
								// Exclude all executable regions from this PE module
								std::uintptr_t end_address = header->get_virtual_size() + base;
								for (auto it = executable_heaps.begin(); it != executable_heaps.end(); )
								{
									if (*it <= end_address && *it >= base)
									{
										// We've accounted for this executable heap, remove it from the loose heap list
										it = executable_heaps.erase(it);
									}
									else
									{
										++it;
									}
								}

								// Check hash
								std::uint64_t hash = header->get_hash();
								if (hash != 0 && !_db_clean->contains(hash) && !output_hashes->contains(hash))
								{
									// Add this to the output hash array
									output_hashes->insert(hash);
								}

								if (output_hashes_ep_shorts)
								{
									// Also get the entrypoint hash
									hash = header->get_hash_ep_short();

									if (hash != 0)
									{
										if (!output_hashes_ep_shorts->contains(hash))
										{
											// Add this to the output hash array
											output_hashes_ep_shorts->insert(hash);
										}
									}

									if (output_hashes_eps)
									{
										// Also get the entrypoint hash
										hash = header->get_hash_ep();

										if (hash != 0 && !output_hashes_eps->contains(hash))
										{
											// Add this to the output hash array
											output_hashes_eps->insert(hash);
										}
									}
								}
							}
						}
					}

					base += PAGE_SIZE;
					++count;
				}
			}

			if (mbi_info.end + 1 <= address)
				break;
			address = mbi_info.end + 1;
		}

		if (_options->DumpChunks)
		{
			// One last loop to add the hashes from all stray executable heaps
			if (_options->Verbose)
				std::println("INFO: Looking at unattached executable heaps...");

			int count_new_header_hashes = 0;
			for (auto heap_base : executable_heaps)
			{
				// Unattached executable page. First check hash of crc32 of first 2kb of memory since import reconstruction hashing is
				// very expensive.

				std::uint64_t chunk_header_hash = this->hash_codechunk_header(heap_base);

				if (_options->Verbose)
					std::println("INFO: Unattached heap start hash 0x{:x}", chunk_header_hash);

				if (chunk_header_hash != 0 && !_db_clean->contains(chunk_header_hash) && !output_hashes->contains(chunk_header_hash))
				{
					if (_options->Verbose)
						std::println("INFO: Unattached heap start hash is new.");

					if (++count_new_header_hashes > CODECHUNK_NEW_HASH_LIMIT)
					{
						if (_options->Verbose)
							std::println("INFO: Too many unique loose code chunks. Stopped processing more chunks.");
						break; // Too many new code chunks
					}

					// Add this header hash
					output_hashes->insert(chunk_header_hash);

					// Calculate the generic import reference hash as well
					auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(heap_base), modules.get(), _options);
					header->build_pe_header(0x1000, true, 1); // 64bit, only build it with the 1 executable section for performance reasons
					header->process_sections();

					// Get the import attributes of this header
					IMPORT_SUMMARY import_summary = header->get_imports_information(&this->_export_list);

					// Check hash
					if (import_summary.HASH_GENERIC != 0 &&
						!_db_clean->contains(import_summary.HASH_GENERIC) &&
						!output_hashes->contains(import_summary.HASH_GENERIC))
					{
						if (_options->Verbose)
						{
							std::println("INFO: Adding hash from unattached heap at 0x{:x} to process hash list: Hash=0x{:x}", 
								heap_base, import_summary.HASH_GENERIC);
						}

						output_hashes->insert(import_summary.HASH_GENERIC);
					}
				}
			}
			if (_options->Verbose)
				std::println("INFO: Done looking at unattached executable heaps...");
		}
	}
	else if (_options->Verbose)
		std::println("INFO: Null process handle {}.", _process_name);

	return false;
}

std::uint64_t dump_process::hash_codechunk_header(std::uintptr_t base) const
{
	std::array<char, CODECHUNK_HEADER_HASH_SIZE> header_buffer{};
	SIZE_T num_read = 0;
	
	BOOL success = ReadProcessMemory(_ph,
		reinterpret_cast<LPCVOID>(base),
		header_buffer.data(),
		CODECHUNK_HEADER_HASH_SIZE,
		&num_read);

	if( ( success || GetLastError() == ERROR_PARTIAL_COPY ) && num_read > 8 && num_read <= CODECHUNK_HEADER_HASH_SIZE )
	{
		// Hash the content
		return static_cast<std::uint64_t>(crc32buf(header_buffer.data(), static_cast<int>(num_read)));
	}
	
	// Default bad hash
	return 0;
}

bool dump_process::build_export_list_for_module(export_list& result, std::string_view library, const module_list& modules) const
{
	// Walk through each module, building the export list for this process. This will be used for import reconstruction
	// Returns: True if there are any modules to dump, False if there is nothing to dump.

	if (!_ph)
		return false;

	bool found = false;

	// Loop through each of these modules, grabbing their exports
	for (const auto& [addr, module_ptr] : modules._modules)
	{
		if (module_ptr && module_ptr->short_name &&
			_strcmpi(module_ptr->short_name, library.data()) == 0)
		{
			auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(addr), const_cast<module_list*>(&modules), _options);
			if (header->process_pe_header() && header->process_sections() && header->process_export_directory())
			{
				// Load its exports
				result.add_export(addr, export_entry(library.data(), "", 0, 0, addr, is64));
				found = true;
			}
		}
	}

	return found;
}

bool dump_process::build_export_list()
{
	// Walk through each module, building the export list for this process. This will be used for import reconstruction
	// Returns: True if there are any modules to dump, False if there is nothing to dump.

	if (!_export_list_built)
	{
		if (!_quieter)
			std::println("... building import reconstruction table ...");

		if (_ph)
		{
			// First build a list of the modules
			auto modules = std::make_unique<module_list>(_pid);

			// Loop through each of these modules, grabbing their exports
			for (const auto& [base_addr, module_ptr] : modules->_modules)
			{
				auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base_addr), modules.get(), _options);
				if (header->process_pe_header() && header->process_sections() && header->process_export_directory())
				{
					// Load its exports
					export_list* module_exports = header->get_exports();
					if (module_exports)
						_export_list.add_exports(*module_exports);
				}
			}
		}
		_export_list_built = true;
	}

	return true;
}

void dump_process::dump_header(pe_header* header, std::uintptr_t base, DWORD pid)
{
	if (!header->process_sections())
		return;
	if (!header->somewhat_parsed())
		return;
	if (!header->process_import_directory())
		return;

	// Check hash
	std::uint64_t hash = header->get_hash();
	if (hash == 0 || _db_clean->contains(hash))
		return;

	if (_options->Verbose)
		std::println(" preparing disk image for '{}' at {:x}", header->get_name(), base);

	if (header->process_disk_image(&_export_list, _db_clean))
	{
		// Build the name that we will dump this image as
		std::string_view extension = "bin";
		if (header->is_exe()) extension = "exe";
		else if (header->is_dll()) extension = "dll";
		else if (header->is_sys()) extension = "sys";

		std::string filename;
		if (_options->output_path && strlen(_options->output_path) > 0)
		{
			filename = std::format("{}\\{}_PID{:x}_{}_{:x}_{}.{}",
				_options->output_path, _process_name, pid,
				header->get_name(), base,
				(header->is_64() ? "x64" : "x86"), extension);
		}
		else
		{
			filename = std::format("{}_PID{:x}_{}_{:x}_{}.{}",
				_process_name, pid,
				header->get_name(), base,
				(header->is_64() ? "x64" : "x86"), extension);
		}

		// Dump the module
		std::println(" dumping '{}' at {:x} to file '{}'", extension, base, filename);
		header->write_image(filename.c_str());
	}
	else if (_options->Verbose)
		std::println("Failed to process disk image for module at {:x}", base);
}

void dump_process::dump_region(std::uintptr_t base)
{
	// Walk through the pages while dumping all MZ files that do not match our good hash database.
	std::println("\ndumping starting at {:x} from process {} with pid 0x{:x}...", 
		base, _process_name, _pid);

	if (!_ph)
		return;

	// First build the export list for this process
	if (!_options->ImportRec || build_export_list())
	{
		auto modules = std::make_unique<module_list>(_pid);
		auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base), modules.get(), _options);

		if (_options->ForceGenHeader || !header->process_pe_header())
		{
			if (_options->Verbose)
				std::println("Generating 32-bit PE header for module at {:x}.", base);

			// Build the pe header as 32 and 64 bit since it could be either
			header->build_pe_header(0x1000ffff, true);
			dump_header(header.get(), base, _pid);

			if (_options->Verbose)
				std::println("Generating 64-bit PE header for module at {:x}.", base);

			header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base), modules.get(), _options);
			header->build_pe_header(0x1000ffff, false);
			dump_header(header.get(), base, _pid);
		}
		else
		{
			if (_options->Verbose)
				std::println("Using existing PE header for module at {:x}.", base);
			dump_header(header.get(), base, _pid);
		}
	}
	else
		std::println("Failed to build export list.");
}

bool dump_process::monitor_close_start()
{
	if (!_opened || _address_main_module == 0)
		return false; // Not attached well to this process

	if (!_term_hook)
	{
		// Add a hook on for when the process terminates so that we can dump it.
		if( _options->Verbose )
			std::println("Hooking process terminate for process {}...", _process_name);
		_term_hook = std::make_unique<terminate_monitor_hook>(_ph, _pid, this->is64(), _options);

		// Load the exports needed for the hooks
		auto modules = std::make_unique<module_list>(_pid);
		export_list exports;
		build_export_list_for_module(exports, "kernel32.dll", *modules);
		build_export_list_for_module(exports, "ntdll.dll", *modules);

		return _term_hook->hook_terminate(&exports);
	}

	return true; // Already started
}

bool dump_process::monitor_close_is_waiting() const
{
	return _term_hook && _term_hook->is_terminate_waiting();
}

bool dump_process::monitor_close_stop()
{
	_term_hook.reset();
	return true;
}

bool dump_process::monitor_close_dump_and_resume()
{
	if (!_term_hook)
		return false;

	if (_term_hook->is_terminate_waiting())
	{
		// Dump the process
		dump_all();

		// Resume it so that it closes normally
		_term_hook->resume_terminate();
		return true;
	}

	return false; // not hooked
}

void dump_process::dump_all()
{
	// Walk through the pages while dumping all MZ files that do not match our good hash database.
	std::println("dumping process {} with pid 0x{:x}...", _process_name, _pid);
	
	if (!_ph)
		return;

	// First build the export list for this process
	if (!build_export_list())
		return;

	// First build a list of the modules
	auto modules = std::make_unique<module_list>(_pid);

	// Set the max address of the target process
	constexpr std::uintptr_t maxAddress = std::numeric_limits<std::uintptr_t>::max();

	// Walk the process heaps
	std::uintptr_t address = 0;

	// First loop to build a list of executable heaps for later use in locating loose executable heaps not associated with any modules
	std::set<std::uintptr_t> executable_heaps;
	if (_options->DumpChunks)
	{
		while (address < maxAddress)
		{
			MBI_BASIC_INFO mbi_info = get_mbi_info(address);
			// Check if this is a loose executable heap (this check causes it to fail.)
			if (mbi_info.base > 0 && mbi_info.end > 0 &&
				mbi_info.valid && mbi_info.executable)
			{
				executable_heaps.insert(mbi_info.base);
			}

			if (mbi_info.end + 1 <= address)
				break;
			address = mbi_info.end + 1;
		}
	}

	// Load all the PE files in the process
	address = 0;
	while (address < maxAddress)
	{
		MBI_BASIC_INFO mbi_info = get_mbi_info(address);

		// Check if this is a loose executable heap
		if (mbi_info.base > 0 && mbi_info.end > 0 && mbi_info.valid)
		{
			if (_options->Verbose)
			{
				std::println("INFO: Scanning from region from 0x{:x} to 0x{:x} for MZ headers.", 
					mbi_info.base, mbi_info.end);
			}

			// This heap may have a PE file, check all page alignments for a "MZ".
			std::uintptr_t base = mbi_info.base - (mbi_info.base % PAGE_SIZE); // shouldn't be required.

			std::array<char, 2> output{};
			SIZE_T out_read{};
			int count = 0;

			while (base + 0x300 < mbi_info.end && count < 1000) // Skip the rest of the section if we have looped over 1000 pages.
			{
				if (ReadProcessMemory(_ph, reinterpret_cast<LPCVOID>(base), output.data(), 2, &out_read) && out_read == 2)
				{
					if (output[0] == 'M' && output[1] == 'Z')
					{
						// Bingo, possible MZ file
						auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base), modules.get(), _options);

						// Use the existing PE header for the dumping
						if (header->process_pe_header())
						{
							if (header->process_sections() && header->somewhat_parsed() && header->process_import_directory())
							{
								// Exclude all executable regions from this PE module
								std::uintptr_t end_address = header->get_virtual_size() + base;

								for (auto it = executable_heaps.begin(); it != executable_heaps.end(); )
								{
									if (*it <= end_address && *it >= base)
									{
										// We've accounted for this executable heap, remove it from the loose heap list
										it = executable_heaps.erase(it);
									}
									else
									{
										++it;
									}
								}

								// Check hash
								std::uint64_t hash = header->get_hash();

								if (hash != 0 && !_db_clean->contains(hash))
								{
									if (_options->ForceGenHeader)
									{
										// Use the existing PE header only to get the hash, then generate a PE header for the dumping.
										std::println("Dumping a module but ignoring existing PE Header for module at 0x{:x}.", base);

										auto header_dump = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base), modules.get(), _options);
										header_dump->build_pe_header(0x1000, true); // 64bit
										dump_header(header_dump.get(), base, _pid);

										header_dump = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(base), modules.get(), _options);
										header_dump->build_pe_header(0x1000, false); // 32bit
										dump_header(header_dump.get(), base, _pid);
									}
									else if (header->process_disk_image(&this->_export_list, this->_db_clean))
									{
										// Build the name that we will dump this image as
										std::string_view extension = "bin";
										if (header->is_exe()) extension = "exe";
										else if (header->is_dll()) extension = "dll";
										else if (header->is_sys()) extension = "sys";

										std::string filename;
										if (_options->output_path && strlen(_options->output_path) > 0)
										{
											filename = std::format("{}\\{}_PID{:x}_{}_{:x}_{}.{}",
												_options->output_path, _process_name, _pid,
												header->get_name(), base,
												(header->is_64() ? "x64" : "x86"), extension);
										}
										else
										{
											filename = std::format("{}_PID{:x}_{}_{:x}_{}.{}",
												_process_name, _pid,
												header->get_name(), base,
												(header->is_64() ? "x64" : "x86"), extension);
										}

										// Dump the module
										std::println("Dumping '{}' at {:x} to file '{}'", extension, base, filename);
										header->write_image(filename.c_str());
									}
								}
							}
						}
					}
				}

				base += PAGE_SIZE;
				++count;
			}
		}

		if (mbi_info.end + 1 <= address)
			break;
		address = mbi_info.end + 1;
	}

	if (_options->DumpChunks)
	{
		// One last loop to add the hashes from all stray executable heaps
		if (_options->Verbose)
			std::println("INFO: Looking at unattached executable heaps...");

		int count_new_header_hashes = 0;
		for (auto heap_base : executable_heaps)
		{
			// Unattached executable page. First check hash of crc32 of first 2kb of memory since import reconstruction hashing is
			// very expensive.

			std::uint64_t chunk_header_hash = this->hash_codechunk_header(heap_base);

			if (_options->Verbose)
				std::println("INFO: Unattached heap start hash 0x{:x}", chunk_header_hash);

			if (chunk_header_hash != 0 && !_db_clean->contains(chunk_header_hash))
			{
				if (_options->Verbose)
					std::println("INFO: Unattached heap start hash is new.");

				if (++count_new_header_hashes > CODECHUNK_NEW_HASH_LIMIT)
				{
					if (_options->Verbose)
						std::println("INFO: Too many unique loose code chunks. Stopped processing more chunks.");
					break; // Too many new code chunks
				}

				// Calculate the generic import reference hash as well
				auto header = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(heap_base), modules.get(), _options);
				header->build_pe_header(0x1000, true, 1); // 64bit, only build it with the 1 executable section for performance reasons
				header->process_sections();

				// Get the import attributes of this header
				IMPORT_SUMMARY import_summary = header->get_imports_information(&this->_export_list);

				// Check hash
				if (import_summary.HASH_GENERIC != 0 && !_db_clean->contains(import_summary.HASH_GENERIC))
				{
					if (_options->Verbose)
					{
						std::println("INFO: Unattached executable heap at 0x{:x} found with {} imports matched.",
							heap_base, import_summary.COUNT_UNIQUE_IMPORT_ADDRESSES);
					}

					if (header->somewhat_parsed() && import_summary.COUNT_UNIQUE_IMPORT_ADDRESSES >= 2) // Require at least 2 imports for dumping
					{
						std::println("Dumping unattached executable code chunk from 0x{:x}.", heap_base);

						auto header_dump = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(heap_base), modules.get(), _options);
						header_dump->build_pe_header(0x1000, true); // 64bit
						header_dump->set_name("codechunk");
						dump_header(header_dump.get(), heap_base, _pid);
						
						header_dump = std::make_unique<pe_header>(_pid, reinterpret_cast<void*>(heap_base), modules.get(), _options);
						header_dump->build_pe_header(0x1000, false); // 32bit

						header_dump->set_name("codechunk");
						dump_header(header_dump.get(), heap_base, _pid);
					}
				}
			}
		}

		if (_options->Verbose)
			std::println("INFO: Done looking at unattached executable heaps...");
	}
}

dump_process::~dump_process()
{
	if (_ph && _ph != INVALID_HANDLE_VALUE)
	{
		CloseHandle(_ph);
	}
}

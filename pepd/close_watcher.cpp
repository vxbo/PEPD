#include "close_watcher.hpp"
#include <print>
#include <ranges>
#include <codecvt>
#include <unordered_map>
#include <chrono>

namespace views = std::views;
using namespace std::chrono_literals;

close_watcher::close_watcher(pe_hash_database* clean_db, PEPD_OPTIONS* options) noexcept
	: _clean_db(clean_db)
	, _options(options)
{
}

void close_watcher::start_monitor() noexcept
{
	// Create the main monitoring thread
	if (!_monitoring_thread.joinable())
	{
		_stop_source = std::stop_source{};
		_monitoring_thread = std::jthread(&close_watcher::_monitor_dump_on_close, this, _stop_source.get_token());

		std::println("Started monitoring for process closes.");
	}
}

void close_watcher::stop_monitor() noexcept
{
	if (!_monitoring_thread.joinable())
	{
		// Request all threads to stop
		_stop_source.request_stop();

		// Clear threads
		_monitoring_thread = std::jthread{};
		_worker_threads.clear();

		std::println("Stopped monitoring for process closes.");
	}
}

void close_watcher::_monitor_dump_on_close(std::stop_token stop_token)
{
	// List of processes hooked
	std::unordered_set<DWORD> hooked_pids;
	std::unordered_map<DWORD, std::unique_ptr<dump_process>> hooked_processes;

	// Create our threads that process the dumping of processes as they close
	_worker_threads.reserve(static_cast<size_t>(_options->NumberOfThreads));

	for ([[maybe_unused]] auto _ : views::iota(0, _options->NumberOfThreads))
		_worker_threads.emplace_back(&close_watcher::_dump_process_worker_and_close, this, _stop_source.get_token());

	// Hook all processes terminates
	PROCESSENTRY32 entry{ .dwSize = sizeof(PROCESSENTRY32) };
	const DWORD myPid = GetCurrentProcessId();

	while (!_stop_source.stop_requested())
	{
		// Keep hooking any new processes
		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot != INVALID_HANDLE_VALUE)
		{
			if (Process32First(snapshot, &entry) == TRUE)
			{
				do
				{
					if ( myPid != entry.th32ProcessID && hooked_pids.count(entry.th32ProcessID) == 0)
					{
						if (_wcsicmp(entry.szExeFile, L"csrss.exe") != 0) // TEMPORARY FIX TO ISSUE #10 CRASHING CSRSS.EXE
						{
							// Test code to only hook notepad.exe
							//if (_wcsicmp(entry.szExeFile, L"notepad.exe") == 0)
							//{
								// New process
								auto dumper = std::make_unique<dump_process>(entry.th32ProcessID, _clean_db, _options, true);
								if (dumper->monitor_close_start())
								{
									std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
									std::string name = converter.to_bytes(entry.szExeFile);
									std::println("...hooked close of: PID 0x{:x}, {}", entry.th32ProcessID, name);

									const DWORD pid = dumper->get_pid();

									hooked_pids.insert(pid);
									hooked_processes.emplace(pid, std::move(dumper));
								}
							//}
						}
					}
				} while (Process32Next(snapshot, &entry) == TRUE);
			}

			CloseHandle(snapshot);
		}

		// Check if any processes are waiting to close
		for (auto it = hooked_processes.begin(); it != hooked_processes.end(); )
		{
			if (it->second->monitor_close_is_waiting())
			{
				// Dump this process by adding it to the multi-threaded dumping queue

				std::println("Process {} requesting to close, we are dumping it...", it->second->get_process_name());

				// Transfer ownership from hooked map
				_work_queue.push(std::move(it->second));

				// Remove this process from hooked map
				it = hooked_processes.erase(it);
			}
			else
			{
				++it;
			}
		}

		std::this_thread::sleep_for(10ms);
	}

	// Wait for the work queue to finish processing
	while (!_work_queue.empty() && !stop_token.stop_requested())
	{
		std::println("Waiting for dump commands to be pulled from work queue...");
		std::this_thread::sleep_for(200ms);
	}

	// Request worker threads to stop
	_stop_source.request_stop();
}

void close_watcher::_dump_process_worker_and_close(std::stop_token stop_token)
{
	while (!stop_token.stop_requested() || !_work_queue.empty())
	{
		// Process the hashes for this process
		if (_work_queue.empty())
		{
			// Process this process

			auto entry = std::move(_work_queue.front());
			_work_queue.pop();

			// Dump this process
			if (entry)
				entry->monitor_close_dump_and_resume();
		}

		std::this_thread::sleep_for(10ms);
	}
}

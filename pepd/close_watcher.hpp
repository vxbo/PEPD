#pragma once

#include <thread>
#include "pe_hash_database.hpp"
#include "dump_process.hpp"
#include <Windows.h>
#include <queue>
#include "simple.hpp"

class close_watcher
{
private:
	pe_hash_database* _clean_db;
	PEPD_OPTIONS* _options;

	std::queue<std::unique_ptr<dump_process>> _work_queue;
	std::jthread _monitoring_thread;
	std::stop_source _stop_source;
	std::vector<std::jthread> _worker_threads;

	void _monitor_dump_on_close(std::stop_token stop_token);
	void _dump_process_worker_and_close(std::stop_token stop_token);

public:
	explicit close_watcher(pe_hash_database* clean_db, PEPD_OPTIONS* options) noexcept;

	~close_watcher() = default;
	close_watcher(const close_watcher&) = delete;
	close_watcher& operator=(const close_watcher&) = delete;
	close_watcher(close_watcher&&) noexcept = default;
	close_watcher& operator=(close_watcher&&) noexcept = default;

	// These should be void since always return true
	/*[[nodiscard]]*/ void start_monitor() noexcept;
	/*[[nodiscard]]*/ void stop_monitor() noexcept;
};

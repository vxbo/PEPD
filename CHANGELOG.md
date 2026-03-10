# PEPD

#### Version 2.3 (PLACEHOLDER)

* PLACEHOLDER

---

# Process Dump

#### Version 2.1 (February 12th, 2017)

* Fixed a bug where the last section in some cases would instead be filled with zeros. Thanks to megastupidmonkey for reporting this issue.
* Fixed a bug where 64-bit base addresses would be truncated to a 32-bit address. It now properly keeps the full 64-bit module base address. Thanks to megastupidmonkey for reporting this issue.
* Addressed an issue where the processes dump close monitor would crash csrss.exe.
* Stopped Process Dump from hooking it's own process in close monitor mode. 

#### Version 2.0 (September 18th, 2016)

* Added new flag '-closemon' which runs Process Dump in a monitoring mode. It will pause and dump any process just as it closes. This is designed to work well with malware analysis sandboxes, to be sure to dump malware from memory before the malicious process closes.
* Upgraded Process Dump to be multi-threaded. Commands that dump or get hashes from multiple processes will run separate threads per operation. Default number of threads is 16, which speeds up the general Process Dump dumping processing significantly.
* Upgraded Process Dump to dump unattached code chunks found in memory. These are identified as executable regions in memory which are not attached to a module and do not have a PE header. It also requires that the codechunk refer to at least 2 imports to be considered valid in order to reduce noise. When dumped, a PE header is recreated along with an import table. Code chunks are fully supported by the clean hash database.
* Added flags to control the filepath to the clean hash database as well as the output folder for dumped files.
* Fix to generating clean hash database from user path that was causing a crash.
* Fix to the flag '-g' that forces generation of PE headers. Before even if this flag was set, system dumps (-system), would ignore this flag when dumping a process.
* Various performance improvements.
* Upgraded project to VS2015.

#### Version 1.5 (November 21st, 2015)

* Fixed bug where very large memory regions would cause Process Dump to hang.
* Fixed bug where some modules at high addresses would not be found under 64-bit Windows.
* More debug information now outputted under Verbose mode.

#### Version 1.4 (April 18th, 2015)

* Added new aggressive import reconstruction approach. Now patches up all DWORDs and QWORDs in the module to the corresponding export match.
* Added '-a (address to dump)' flag to dump a specific address. It will generate PE headers and build an import table for the address.
* Added '-ni' flag to skip new import reconstruction algorithm.
* Added '-g' flag to force generation of new PE header even if there exists one when dumping a module. This is good if the PE header is malformed for example.
* Various bug fixes.

#### Version 1.3 (October 10th, 2013)

* Improved handling of PE headers with sections that specify invalid virtual sizes and addresses.
* Better module dumping methodology for dumping virtual sections down to disk sections.

#### Version 1.1 (April 8th, 2013)

* Fixed a compatibility issue with Windows XP.
* Corrected bug where process dump would print it is dumping a module but not actually dump it.
* Implemented the '-pid ' dump flag.

#### Version 1.0 (April 2nd, 2013)

* Initial release.

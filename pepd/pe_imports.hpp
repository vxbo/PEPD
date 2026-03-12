#pragma once
#include "windows.h"
#include <vector>
#include "utils.hpp"

class import_library
{
private:
	const char* _library_name;
	
	IMAGE_IMPORT_DESCRIPTOR* _descriptor;
	IMAGE_THUNK_DATA64* _thunk_entry; // Use 64 bit definition for both 32 and 64 bit modules.
	IMAGE_IMPORT_BY_NAME* _import_by_name; // IMAGE_IMPORT_BY_NAME
	int _import_by_name_len;

public:
	import_library(IMAGE_IMPORT_DESCRIPTOR* descriptor, bool win64);
	import_library(const char* library_name, WORD ordinal, __int64 rva, bool win64);
	import_library(const char* library_name, const char* proc_name, __int64 rva, bool win64);

	bool build_table(unsigned char* section, __int64 section_size, __int64 section_rva, __int64 &descriptor_offset, __int64 &extra_offset);
	void get_table_size(__int64 &descriptor_size, __int64 &extra_size);
	// stub
	/*char* GetName();*/
	~import_library(void);
};

class pe_imports
{
private:
	bool _win64;
	std::vector<import_library*> _libraries;
public:
	pe_imports(unsigned char* image, __int64 image_size, IMAGE_IMPORT_DESCRIPTOR* imports, bool win64);
	void add_descriptor(IMAGE_IMPORT_DESCRIPTOR* descriptor);
	bool build_table(unsigned char* section, __int64 section_size, __int64 section_rva, __int64 descriptor_offset, __int64 extra_offset);
	void get_table_size(__int64 &descriptor_size, __int64 &extra_size);

	void add_fixup(const char* library_name, WORD ordinal, __int64 rva, bool win64);
	void add_fixup(const char* library_name, const char* proc_name, __int64 rva, bool win64);
	//char* build_table();
	~pe_imports(void);
};



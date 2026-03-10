#pragma once

#include <windows.h>
#include <strsafe.h>
#include <string>
#include <iostream>
#include "windows.h"
#include <tlhelp32.h>
#include <Psapi.h>
#include <regex>

using namespace std;

class PEPD_OPTIONS
{
public:
	bool ImportRec;
	bool ForceGenHeader;
	bool Verbose;
	bool ReconstructHeaderAsDll;
	bool DumpChunks; // Dump loose code chunks
	bool EntryPointHash;
	bool ForceReconstructEntryPoint;
	int NumberOfThreads;

	__int64 EntryPointOverride;
	char* output_path;

	//PEPD_OPTIONS()
	//{
	//	output_path = new char[1];
	//	strcpy(output_path,"");
	//}

	void set_output_path( char* path )
	{
		if( output_path != NULL )
			delete[] output_path;

		output_path = new char[strlen(path) + 1];
		strcpy_s( output_path, strlen(path) + 1, path);
	}

	~PEPD_OPTIONS()
	{
		if( output_path != NULL )
		{
			delete[] output_path;
		}
	}
};

class process_description
{
public:
	char* process_name;
	DWORD pid;

	process_description(char* name, DWORD pid)
	{
		process_name = new char[strlen(name)+1];
		strcpy( process_name, name );
		this->pid = pid;
	}
	
	~process_description()
	{
		delete[] process_name;
	}
};

size_t process_find(string match_regex, std::vector<process_description*>* result);
string ExePath();
void PrintLastError(LPTSTR lpszFunction); 
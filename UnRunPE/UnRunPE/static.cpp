#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <Windows.h>

#include "static.h"
#include "Util.h"

// runpe import functions
std::map<std::string, bool> imports = { { "CreateProcessA", false },{ "CreateProcessW", false },{ "CreateProcessInternalA", false },{ "CreateProcessInternalW", false },
										{ "VirtualAllocEx", false },{ "WriteProcessMemory", false },{ "GetThreadContext", false },{ "SetThreadContext", false },
										{ "Wow64GetThreadContext", false },{ "Wow64SetThreadContext", false },{ "ResumeThread", false },{ "NtCreateUserProcess", false },
										{ "ZwCreateUserProcess", false },{ "NtGetContextThread", false },{ "NtGetContextThread", false },{ "NtSetContextThread", false },
										{ "ZwGetContextThread", false },{ "ZwSetContextThread", false },{ "RtlCreateUserProcess", false },{ "RtlCreateUserProcess", false },
										{ "NtCreateUserProcess", false },{ "ZwCreateUserProcess", false },{ "NtResumeThread", false },{ "ZwResumeThread", false },
										{ "NtUnmapViewOfSection", false },{ "ZwUnmapViewOfSection", false } };

/*
* Map PE file into memory
*/
static bool memoryMapPayload(const LPVOID lpDest, const LPVOID lpPayload, const PIMAGE_DOS_HEADER pidh, const PIMAGE_NT_HEADERS pinh) {
	// copy section headers
	CopyMemory(lpDest, lpPayload, pinh->OptionalHeader.SizeOfHeaders);

	// copy each section individually at virtual address
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)lpPayload + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
		CopyMemory(((LPBYTE)lpDest + pish->VirtualAddress), ((LPBYTE)lpPayload + pish->PointerToRawData), pish->SizeOfRawData);
	}

	return true;
}

/*
* Walk the import table and fix the addresses
*/
static bool checkImportTable(const LPVOID lpBaseAddress, const PIMAGE_NT_HEADERS pinh, std::map<std::string, bool>& imports) {
	bool ret = false;
	// parse import table if size != 0
	if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		// https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
		while (pImportDescriptor->Name) {
			PIMAGE_THUNK_DATA nameRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress) + pImportDescriptor->Characteristics);
			PIMAGE_THUNK_DATA symbolRef = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress) + pImportDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA lpThunk = (PIMAGE_THUNK_DATA)((DWORD)(lpBaseAddress) + pImportDescriptor->FirstThunk);
			for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
				// fix addresses
				// check if import by ordinal
				if (!(nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG)) {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((DWORD)(lpBaseAddress) + nameRef->u1.AddressOfData);
					std::string importName((LPCSTR)(&thunkData->Name));
					for (std::map<std::string, bool>::iterator iter = imports.begin(); iter != imports.end(); ++iter) {
						if (!iter->first.compare(importName)) {
							iter->second = true;
							ret = true;
						}
					}
				}
			}
			pImportDescriptor++;
		}
	}

	return ret;
}

static bool read(const std::string fileName, std::vector<BYTE>& data) {
	// open handle to file
	DWORD dwAttributes = ::GetFileAttributesA(fileName.c_str());
	HANDLE hFile = ::CreateFileA(fileName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, dwAttributes, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwRead = 0;
	DWORD dwSize = ::GetFileSize(hFile, nullptr);
	std::vector<BYTE> file(dwSize);
	if (!::ReadFile(hFile, &file[0], dwSize, &dwRead, nullptr)) {
		::CloseHandle(hFile);
		return false;
	}

	data = file;

	return true;
}

bool staticAnalyse(const std::string fileName) {
	// read into vector
	std::vector<BYTE> file;
	if (!read(fileName, file))
		return false;

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)file.data();
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)(file.data() + pidh->e_lfanew);

	// check PE file
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE || pinh->Signature != IMAGE_NT_SIGNATURE) {
		::SetLastError(ERROR_BAD_EXE_FORMAT);
		return false;
	}

	// map payload to memory
	LPBYTE lpAddress = new BYTE[pinh->OptionalHeader.SizeOfImage];
	if (memoryMapPayload(lpAddress, file.data(), pidh, pinh)) {
		// walk import table
		Util::Debug<Util::DebugType::INFO>("Scanning for suspicious imports...\n");
		if (checkImportTable(lpAddress, pinh, imports)) {
			//std::cout << "[!] Suspicious imports found:\n";
			Util::Debug<Util::DebugType::WARNING>("Suspicious imports found:\n");
			for (const auto import : imports) {
				if (import.second)
					//std::cout << ">>> " << import.first << "\n";
					Util::Debug<Util::DebugType::CHILD>(import.first + "\n");
			}
		} else
			//std::cout << "[*] No suspicious imports found.\n";
			Util::Debug<Util::DebugType::INFO>("No suspicious imports found\n");
	}
	std::cout << "\n";

	delete lpAddress;
	
	return true;
}

bool stringSearch(const std::string haystack, std::map<std::string, bool>& imports) {
	// return true if strings found
	bool ret = false;

	// set into std::string
	Util::Debug<Util::DebugType::INFO>("Scanning for suspicious strings...\n");
	for (std::map<std::string, bool>::iterator iter = imports.begin(); iter != imports.end(); ++iter) {
		if (haystack.find(iter->first) != std::string::npos) {
			iter->second = true;
			ret = true;
		}
	}

	// again for lowercase
	for (std::map<std::string, bool>::iterator iter = imports.begin(); iter != imports.end(); ++iter) {
		// check if string already found
		if (!iter->second) {
			std::string lowercase = iter->first;
			std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(), ::tolower);
			if (haystack.find(lowercase) != std::string::npos) {
				iter->second = true;
				ret = true;
			}
		}
	}

	return ret;
}

bool stringAnalyse(const std::string fileName) {
	// read into vector
	std::vector<BYTE> file;
	if (!read(fileName, file))
		return false;

	std::string haystack(file.data(), file.data() + file.size());
	if (stringSearch(haystack, imports)) {
		Util::Debug<Util::DebugType::WARNING>("Suspicious strings found:\n");
		for (const auto import : imports)
			if (import.second)
				Util::Debug<Util::DebugType::CHILD>(import.first + "\n");
	} else
		Util::Debug<Util::DebugType::INFO>("No suspicious strings found\n");

	std::cout << "\n";

	return true;
}
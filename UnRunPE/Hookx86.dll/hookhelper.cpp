#include <Windows.h>
#include <TlHelp32.h>

#include "hookhelper.h"
#include "hooks.h"
#include "Util.h"

fpNtQueryInformationThread fNtQueryInformationThread = nullptr;

fpNtCreateUserProcess fNtCreateUserProcess = nullptr;
fpNtUnmapViewOfSection fNtUnmapViewOfSection = nullptr;
fpNtAllocateVirtualMemory fNtAllocateVirtualMemory = nullptr;
fpNtWriteVirtualMemory fNtWriteVirtualMemory = nullptr;
fpNtGetContextThread fNtGetContextThread = nullptr;
fpNtSetContextThread fNtSetContextThread = nullptr;
fpNtResumeThread fNtResumeThread = nullptr;

std::map<std::string, LPBYTE> g_originalBytes;
HANDLE g_hHookedProcess = nullptr;
HMODULE g_hNtDll = nullptr;
DWORD g_dwThreadId = 0;

bool getMainThreadId(DWORD *pdwThreadId) {
	bool bResult = false;

	ULONG_PTR nModuleBaseAddress = (ULONG_PTR)GetModuleHandle(nullptr);
	if (!nModuleBaseAddress)
		return false;

	IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER *)nModuleBaseAddress;
	if (!pDos)
		return false;

	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)((ULONG_PTR)pDos + pDos->e_lfanew);
	if (!pNtHeaders)
		return false;

	HANDLE hThreadQuery = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hThreadQuery == INVALID_HANDLE_VALUE)
		return false;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	if (::Thread32First(hThreadQuery, &te)) {
		do {
			if (te.th32OwnerProcessID != ::GetCurrentProcessId())
				continue;

			HANDLE hThreadHandle = ::OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);

			if (hThreadHandle == nullptr)
				continue;

			ULONG len;
			ULONG_PTR nThreadStartAddress;
			fNtQueryInformationThread = (fpNtQueryInformationThread)::GetProcAddress(g_hNtDll, "NtQueryInformationThread");
			if (NT_SUCCESS(fNtQueryInformationThread(hThreadHandle, ThreadQuerySetWin32StartAddress, &nThreadStartAddress, sizeof(nThreadStartAddress), &len))) {
				if ((nModuleBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint) == nThreadStartAddress) {
					bResult = true;
					*pdwThreadId = te.th32ThreadID;
				}
			}
			::CloseHandle(hThreadHandle);
		} while (::Thread32Next(hThreadQuery, &te) && bResult == false);
	}

	::CloseHandle(hThreadQuery);

	return bResult;
}

void initialiseHooks() {
	//std::cout << "[*] Initializing hooks...\n";
	Util::Log<Util::DebugType::INFO>("Initialising hooks...\n");
	// get dll handle
	g_hNtDll = ::GetModuleHandle(L"ntdll.dll");

	if (!g_hNtDll)
		Util::FatalLog("Failed to obtain DLL handles.\n");

	// hook functions
	LPBYTE bytes = nullptr;
	fNtCreateUserProcess = (fpNtCreateUserProcess)::GetProcAddress(g_hNtDll, "ZwCreateUserProcess");
	if (!fNtCreateUserProcess)
		Util::FatalLog("Failed to obtain NtCreateUserProcess.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtCreateUserProcess, (DWORD)HookedNtCreateUserProcess);
	g_originalBytes.insert({ "NtCreateUserProcess", bytes });

	fNtUnmapViewOfSection = (fpNtUnmapViewOfSection)::GetProcAddress(g_hNtDll, "ZwUnmapViewOfSection");
	if (!fNtUnmapViewOfSection)
		Util::FatalLog("Failed to obtain NtUnmapViewOfSection.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtUnmapViewOfSection, (DWORD)HookedNtUnmapViewOfSection);
	g_originalBytes.insert({ "NtUnmapViewOfSection", bytes });

	//fNtAllocateVirtualMemory = (fpNtAllocateVirtualMemory)::GetProcAddress(g_hNtDll, "NtAllocateVirtualMemory");
	//if (!fNtAllocateVirtualMemory)
	//	Util::FatalLog("Failed to obtain NtAllocateVirtualMemory.\n");
	//bytes = Util::Memory::HookFunction((DWORD)fNtAllocateVirtualMemory, (DWORD)HookedNtAllocateVirtualMemory);
	//g_originalBytes.insert({ "NtAllocateVirtualMemory", bytes });

	fNtWriteVirtualMemory = (fpNtWriteVirtualMemory)::GetProcAddress(g_hNtDll, "NtWriteVirtualMemory");
	if (!fNtWriteVirtualMemory)
		Util::FatalLog("Failed to obtain NtWriteVirtualMemory.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtWriteVirtualMemory, (DWORD)HookedNtWriteVirtualMemory);
	g_originalBytes.insert({ "NtWriteVirtualMemory", bytes });

	fNtGetContextThread = (fpNtGetContextThread)::GetProcAddress(g_hNtDll, "NtGetContextThread");
	if (!fNtGetContextThread)
		Util::FatalLog("Failed to obtain NtGetContextThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtGetContextThread, (DWORD)HookedNtGetContextThread);
	g_originalBytes.insert({ "NtGetContextThread", bytes });

	fNtSetContextThread = (fpNtSetContextThread)::GetProcAddress(g_hNtDll, "NtSetContextThread");
	if (!fNtSetContextThread)
		Util::FatalLog("Failed to obtain NtSetContextThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtSetContextThread, (DWORD)HookedNtSetContextThread);
	g_originalBytes.insert({ "NtSetContextThread", bytes });

	fNtResumeThread = (fpNtResumeThread)::GetProcAddress(g_hNtDll, "NtResumeThread");
	if (!fNtResumeThread)
		Util::FatalLog("Failed to obtain NtResumeThread.\n");
	bytes = Util::Memory::HookFunction((DWORD)fNtResumeThread, (DWORD)HookedNtResumeThread);
	g_originalBytes.insert({ "NtResumeThread", bytes });

	// get own process handle to compare later
	g_hHookedProcess = ::GetCurrentProcess();

	//std::cout << "[*] Success!\n\n";
	Util::Log<Util::DebugType::ADD>("Success!\n\n");
	
	// get original thread to check in hooks
	getMainThreadId(&g_dwThreadId);

	//::Sleep(10000);

	// resume thread
	HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, false, g_dwThreadId);
	if (hThread)
		::ResumeThread(hThread);
	else
		Util::FatalLog("Failed to resume thread\n");
}

void virtualToRaw(std::vector<BYTE>& out, const std::vector<BYTE>& in) {
	// get headers
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)in.data();
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)in.data() + pidh->e_lfanew);

	// start raw size with size of headers
	DWORD dwSize = pinh->OptionalHeader.SizeOfHeaders;
	// get rest of raw size
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
		dwSize += pish->SizeOfRawData;
	}

	// now allocate raw vector
	std::vector<BYTE> raw(dwSize);

	// copy headers
	//raw.insert(raw.begin(), in.begin(), in.begin() + pinh->OptionalHeader.SizeOfHeaders);
	std::copy(in.data(), in.data() + pinh->OptionalHeader.SizeOfHeaders, raw.begin());
	// copy sections
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
		if (pish->SizeOfRawData > 0)
			std::copy(in.data() + pish->VirtualAddress, in.data() + pish->VirtualAddress + pish->SizeOfRawData, raw.begin() + pish->PointerToRawData);
	}

	out = raw;
}

bool dumpPe(const std::string fileName, LPVOID lpBuffer, const DWORD dwSize) {
	Util::Log<Util::DebugType::INFO>("Dumping to \"" + fileName + "\"...\n");

	HANDLE hFile = ::CreateFileA(fileName.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {\
		Util::Log<Util::DebugType::SUB>("Failed to create dump file; error: " + std::to_string(::GetLastError()) + "\n\n");
		return false;
	}

	DWORD dwWritten = 0;
	if (!::WriteFile(hFile, lpBuffer, dwSize, &dwWritten, nullptr)) {
		::CloseHandle(hFile);\
		Util::Log<Util::DebugType::SUB>("Failed to write to dump file; error: " + std::to_string(::GetLastError()) + "\n\n");
		return false;
	}

	::CloseHandle(hFile);
	\
	Util::Log<Util::DebugType::ADD>("Successfully dumped " + std::to_string(dwWritten) + " bytes to \"" + fileName + "\n\n");

	return true;
}
#include <cctype>

#include "hooks.h"
#include "Util.h"

DWORD g_dwProcessId = 0;
//DWORD g_dwRegionSize = 0;
DWORD g_dwImageBase = 0;

NTSTATUS NTAPI HookedNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {
	if (::GetCurrentThreadId() == g_dwThreadId) {
		Util::Log<Util::DebugType::INFO>("Hooked NtCreateUserProcess!\n");
		Util::DebugW<Util::DebugType::CHILD>(L"Image path name: " + std::wstring(ProcessParameters->ImagePathName.Buffer) + L"\n");
		Util::DebugW<Util::DebugType::CHILD>(L"Command line: " + std::wstring(ProcessParameters->CommandLine.Buffer) + L"\n");
		Util::DebugW<Util::DebugType::CHILD>(L"Current directory path" + std::wstring(ProcessParameters->CurrentDirectoryPath.Buffer) + L"\n");
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtCreateUserProcess, g_originalBytes.find("NtCreateUserProcess")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtCreateUserProcess")->second;

	// call function for process and thread handles
	NTSTATUS ret = ::fNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

	if (::GetCurrentThreadId() == g_dwThreadId) {
		if (NT_SUCCESS(ret)) {
			g_dwProcessId = ::GetProcessId(*ProcessHandle);
			Util::Log<Util::DebugType::CHILD>("Process ID: " + std::to_string(g_dwProcessId) + "\n");
			Util::Log<Util::DebugType::CHILD>("Thread ID: " + std::to_string(::GetThreadId(*ThreadHandle)) + "\n\n");
		}
	}

	// rehook function
	g_originalBytes.find("NtCreateUserProcess")->second = Util::Memory::HookFunction((DWORD)fNtCreateUserProcess, (DWORD)HookedNtCreateUserProcess);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
	if (::GetCurrentThreadId() == g_dwThreadId) {
		Util::Log<Util::DebugType::INFO>("Hooked NtUnmapViewOfSection!\n");
		// save process id
		DWORD dwProcessId = ::GetProcessId(ProcessHandle);
		Util::Log<Util::DebugType::CHILD>("Process ID: " + std::to_string(dwProcessId) + "\n");
		// save base address
		g_dwImageBase = (DWORD)BaseAddress;
		Util::Log<Util::DebugType::CHILD>("Base address: " + std::to_string((DWORD)BaseAddress) + "\n\n");
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtUnmapViewOfSection, g_originalBytes.find("NtUnmapViewOfSection")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtUnmapViewOfSection")->second;

	// call function for process and thread handles
	NTSTATUS ret = fNtUnmapViewOfSection(ProcessHandle, BaseAddress);

	// rehook function
	g_originalBytes.find("NtUnmapViewOfSection")->second = Util::Memory::HookFunction((DWORD)fNtUnmapViewOfSection, (DWORD)HookedNtUnmapViewOfSection);

	// return original call value
	return ret;
}

//NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
//	if (::GetCurrentThreadId() == g_dwThreadId) {
//		//Util::Log<Util::DebugType::INFO>("Hooked NtAllocateVirtualMemory!\n";
//		//DWORD dwProcessId = ::GetProcessId(ProcessHandle);
//		//Util::Log<Util::DebugType::CHILD>("Process ID: " + dwProcessId + ")\n";
//		//Util::Log<Util::DebugType::CHILD>("Base address: " + ::std::hex + (DWORD)BaseAddress + " | Region size: " + *RegionSize + "\n";
//
//		//// format protection value
//		//std::vector<std::string> protectionTypes;
//		//if (Protect & PAGE_NOACCESS) protectionTypes.push_back("PAGE_NOACCESS");
//		//if (Protect & PAGE_READONLY) protectionTypes.push_back("PAGE_READONLY");
//		//if (Protect & PAGE_READWRITE) protectionTypes.push_back("PAGE_READWRITE");
//		//if (Protect & PAGE_EXECUTE) protectionTypes.push_back("PAGE_EXECUTE");
//		//if (Protect & PAGE_EXECUTE_READ) protectionTypes.push_back("PAGE_EXECUTE_READ");
//		//if (Protect & PAGE_EXECUTE_READWRITE) protectionTypes.push_back("PAGE_EXECUTE_READWRITE");
//		//if (Protect & PAGE_EXECUTE_WRITECOPY) protectionTypes.push_back("PAGE_EXECUTE_WRITECOPY");
//
//		//std::string protections;
//		//for (int i = 0; i < protectionTypes.size(); i++) {
//		//	protections += protectionTypes.at(i);
//
//		//	if (i != protectionTypes.size() - 1)
//		//		protections += " | ";
//		//}
//
//		//Util::Log<Util::DebugType::CHILD>("Protection type: " + protections + " (" + std::hex + Protect + ")\n\n";
//	}
//
//	// unhook to call function
//	Util::Memory::UnhookFunction((DWORD)fNtAllocateVirtualMemory, g_originalBytes.find("NtAllocateVirtualMemory")->second);
//	// free original bytes after use
//	delete g_originalBytes.find("NtAllocateVirtualMemory")->second;
//
//	// call function for process and thread handles
//	NTSTATUS ret = fNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
//
//	// save region size for dump
//	if (Protect == 0x40)
//		g_dwRegionSize = *RegionSize;
//
//	// rehook function
//	//g_originalBytes.find("NtAllocateVirtualMemory")->second = Util::Memory::HookFunction((DWORD)fNtAllocateVirtualMemory, (DWORD)HookedNtAllocateVirtualMemory);
//
//	// return original call value
//	return ret;
//}

NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {
	if (::GetCurrentThreadId() == g_dwThreadId) {
		Util::Log<Util::DebugType::INFO>("Hooked NtWriteVirtualMemory!\n");
		DWORD dwProcessId = ::GetProcessId(ProcessHandle);
		Util::Log<Util::DebugType::CHILD>("Process ID: " + std::to_string(dwProcessId) + "\n");
		Util::Log<Util::DebugType::CHILD>("Base address: " + std::to_string((DWORD)BaseAddress) + "\n");
		Util::Log<Util::DebugType::CHILD>("Buffer at " + std::to_string((DWORD)Buffer) + " | Size: " + std::to_string(NumberOfBytesToWrite) + "\n\n");

		// Buffer may hold the PE file
		// dump if MZ header found
		if (*(LPBYTE)Buffer == 'M' && *((LPBYTE)Buffer + 1) == 'Z') {
			// calculate size of raw PE file on disk
			DWORD dwPeSize = 0;
			PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)Buffer;
			PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)Buffer + pidh->e_lfanew);

			// verify PE header
			if (pinh->Signature == IMAGE_NT_SIGNATURE) {
				dwPeSize += pinh->OptionalHeader.SizeOfHeaders;
				for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
					PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
					dwPeSize += pish->SizeOfRawData;
				}

				Util::Log<Util::DebugType::INFO>("DOS magic and PE signature detected! Dumping buffer at [" + std::to_string((DWORD)Buffer) + "] (size: [" + std::to_string(dwPeSize) + "])...\n");

				dumpPe("NtWriteVirtualMemory_dump.bin", Buffer, dwPeSize);
			}
		}

		//std::cout << "\n";
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtWriteVirtualMemory, g_originalBytes.find("NtWriteVirtualMemory")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtWriteVirtualMemory")->second;

	// call function for process and thread handles
	NTSTATUS ret = fNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

	// rehook function
	g_originalBytes.find("NtWriteVirtualMemory")->second = Util::Memory::HookFunction((DWORD)fNtWriteVirtualMemory, (DWORD)HookedNtWriteVirtualMemory);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
	if (::GetCurrentThreadId() == g_dwThreadId) {
		Util::Log<Util::DebugType::INFO>("Hooked NtGetContextThread!\n");
		DWORD dwThreadId = ::GetThreadId(ThreadHandle);
		Util::Log<Util::DebugType::CHILD>("Thread ID: " + std::to_string(dwThreadId) + "\n\n");
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtGetContextThread, g_originalBytes.find("NtGetContextThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtGetContextThread")->second;

	// call function for process and thread handles
	NTSTATUS ret = fNtGetContextThread(ThreadHandle, Context);

	// rehook function
	g_originalBytes.find("NtGetContextThread")->second = Util::Memory::HookFunction((DWORD)fNtGetContextThread, (DWORD)HookedNtGetContextThread);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
	if (::GetCurrentThreadId() == g_dwThreadId) {
		Util::Log<Util::DebugType::INFO>("Hooked NtSetContextThread!\n");
		DWORD dwThreadId = ::GetThreadId(ThreadHandle);
		Util::Log<Util::DebugType::CHILD>("Thread ID: " + std::to_string(dwThreadId) + "\n\n");
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtSetContextThread, g_originalBytes.find("NtSetContextThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtSetContextThread")->second;

	// call function for process and thread handles
	NTSTATUS ret = fNtSetContextThread(ThreadHandle, Context);

	// rehook function
	g_originalBytes.find("NtSetContextThread")->second = Util::Memory::HookFunction((DWORD)fNtSetContextThread, (DWORD)HookedNtSetContextThread);

	// return original call value
	return ret;
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
	if (::GetCurrentThreadId() == g_dwThreadId) {
		Util::Log<Util::DebugType::INFO>("Hooked NtResumeThread!\n");
		DWORD dwThreadId = ::GetThreadId(ThreadHandle);
		Util::Log<Util::DebugType::CHILD>("Thread ID: " + std::to_string(dwThreadId) + "\n\n");

		// unpacked file should be in new process

		// open process
		HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS /*PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_OPERATION*/, false, g_dwProcessId);
		if (!hProcess)
			Util::FatalLog("Failed to open process ID " + g_dwProcessId);
		
		// get image size of child process
		DWORD dwRead = 0;
		std::vector<BYTE> buffer(0x200);	// should be enough for PE headers
		if (!::ReadProcessMemory(hProcess, (LPVOID)g_dwImageBase, &buffer[0], 0x200, &dwRead))
			Util::Log<Util::DebugType::SUB>("Failed to obtain image size of child process ID " + std::to_string(g_dwProcessId) + " error: " + std::to_string(::GetLastError()) + "\n");

		PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)buffer.data();
		PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)buffer.data() + pidh->e_lfanew);
		DWORD dwSizeOfImage = pinh->OptionalHeader.SizeOfImage;

		// explicitly unprotect region
		DWORD flProtect = 0;
		::VirtualProtectEx(hProcess, (LPVOID)g_dwImageBase, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &flProtect);

		// read from image base until region size
		dwRead = 0;
		std::vector<BYTE> pe(dwSizeOfImage);
		if (!::ReadProcessMemory(hProcess, (LPVOID)g_dwImageBase, &pe[0], dwSizeOfImage, &dwRead))
			Util::Log<Util::DebugType::SUB>("Failed to read process ID " + std::to_string(g_dwProcessId) + " error: " + std::to_string(::GetLastError()) + "\n");

		std::vector<BYTE> raw;
		virtualToRaw(raw, pe);

		Util::Log<Util::DebugType::INFO>("Dumping [" + std::to_string(raw.size()) + "] bytes at base address [" + std::to_string(g_dwImageBase) + "] from process ID [" + std::to_string(g_dwProcessId) + "]...\n");
		dumpPe("NtResumeThread_dump.bin", raw.data(), raw.size());

		// terminate process
		Util::Log<Util::DebugType::INFO>("Terminating child process...\n");
		::TerminateProcess(hProcess, 0);
		::CloseHandle(hProcess);

		Util::Log<Util::DebugType::INFO>("Terminating main process...\n");
		::ExitProcess(0);
	}

	// unhook to call function
	Util::Memory::UnhookFunction((DWORD)fNtResumeThread, g_originalBytes.find("NtResumeThread")->second);
	// free original bytes after use
	delete g_originalBytes.find("NtResumeThread")->second;

	// call function for process and thread handles
	NTSTATUS ret = fNtResumeThread(ThreadHandle, SuspendCount);

	// rehook function
	g_originalBytes.find("NtResumeThread")->second = Util::Memory::HookFunction((DWORD)fNtResumeThread, (DWORD)HookedNtResumeThread);

	// return original call value
	return ret;
}
#include <iostream>
#include <string>
#include <Windows.h>

#include "dynamic.h"
#include "Util.h"

bool createChildProcess(const std::string fileName, HANDLE& hProcess, HANDLE& hThread) {
	//SECURITY_ATTRIBUTES sa;
	//HANDLE hChildStd_IN_Rd = nullptr;
	//HANDLE hChildStd_IN_Wr = nullptr;
	//HANDLE hChildStd_OUT_Rd = nullptr;
	//HANDLE hChildStd_OUT_Wr = nullptr;

	// Set the bInheritHandle flag so pipe handles are inherited. 
	//sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	//sa.bInheritHandle = true;
	//sa.lpSecurityDescriptor = nullptr;

	//// Create a pipe for the child process's STDOUT.
	//if (!::CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &sa, 0))
	//	std::cout << "StdoutRd CreatePipe\n";

	//// Ensure the read handle to the pipe for STDOUT is not inherited.
	//if (!::SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
	//	std::cout << "Stdout SetHandleInformation\n";

	//// Create a pipe for the child process's STDIN.
	//if (!::CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &sa, 0))
	//	std::cout << "Stdin CreatePipe\n";

	//// Ensure the write handle to the pipe for STDIN is not inherited. 
	//if (!::SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
	//	std::cout << "Stdin SetHandleInformation\n";

	STARTUPINFOA si;
	::ZeroMemory(&si, sizeof(STARTUPINFOA));
	si.cb = sizeof(STARTUPINFOA);
	//si.dwFlags |= STARTF_USESTDHANDLES;
	//si.hStdError = hChildStd_OUT_Wr;
	//si.hStdOutput = hChildStd_OUT_Wr;
	//si.hStdInput = hChildStd_IN_Rd;

	PROCESS_INFORMATION pi;
	::ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	if (!::CreateProcessA(fileName.c_str(), nullptr, nullptr, nullptr, true, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
		return false;

	hThread = pi.hThread;
	hProcess = pi.hProcess;

	return true;
}

bool injectDll(HANDLE hProcess, std::string dllPath) {
	LPVOID lpBaseAddress = ::VirtualAllocEx(hProcess, nullptr, dllPath.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress) {
		DWORD dwWritten = 0;
		if (::WriteProcessMemory(hProcess, lpBaseAddress, dllPath.c_str(), dllPath.length(), &dwWritten)) {
			HMODULE hModule = ::GetModuleHandle(L"kernel32.dll");
			if (hModule) {
				LPVOID lpStartAddress = ::GetProcAddress(hModule, "LoadLibraryA");
				if (lpStartAddress) {
					if (::CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, nullptr)) {
						return true;
					}
				}
			}
		}
	}

	::VirtualFreeEx(hProcess, lpBaseAddress, dllPath.length(), MEM_DECOMMIT);
	return false;
}

bool dynamicAnalyse(const std::string fileName) {
	// start target file as child process
	Util::Debug<Util::DebugType::INFO>("Creating " + fileName + " as a suspended process...\n");

	HANDLE hProcess = nullptr, hThread = nullptr;
	if (!createChildProcess(fileName, hProcess, hThread))
		return false;
	Util::Debug<Util::DebugType::ADD>("Success!\n\n");

	Util::Debug<Util::DebugType::INFO>("Injecting hook...\n");
	// inject hooking dll
	char currentDir[MAX_PATH + 1];
	::GetCurrentDirectoryA(MAX_PATH, currentDir);

	std::string dllPath = currentDir;
	dllPath += "\\";
	dllPath += DLL_NAME;

	Util::Debug<Util::DebugType::INFO>("Injecting " + dllPath + "\n");

	if (!injectDll(hProcess, dllPath))
		return false;

	Util::Debug<Util::DebugType::INFO>("Awaiting completion...\n");
	::WaitForSingleObject(hProcess, INFINITE);

	DWORD dwExitCode = 0;
	if (::GetExitCodeProcess(hProcess, &dwExitCode)) {
		if (dwExitCode == 0)
			//std::cout << "[*] Process exited successfully!\n";
			Util::Debug<Util::DebugType::ADD>("Process exited successfully!\n");
		else
			//std::cout << "[*] Process exited with error code: " << dwExitCode << "\n";
			Util::Debug<Util::DebugType::WARNING>("Process exited with error code: " + std::to_string(dwExitCode) + "\n");
	}

	::CloseHandle(hThread);
	::CloseHandle(hProcess);

	return true;
}
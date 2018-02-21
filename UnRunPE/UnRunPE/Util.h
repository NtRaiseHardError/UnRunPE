#pragma once
#ifndef __UTIL_H__
#define __UTIL_H__

#include <iostream>
#include <string>
#include <exception>
#include <Windows.h>

#define LIGHT_GREEN FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define DARK_GREEN FOREGROUND_GREEN
#define LIGHT_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define LIGHT_YELLOW FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define LIGHT_BLUE FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define WHITE FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define GRAY FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED

namespace Util {
	enum DebugType {
		INFO,
		WARNING,
		ADD,
		SUB,
		CHILD
	};

	/*
	 * Displays synchronous message box.
	 * PARAM fmt : format string
	 * PARAM args : variadic arguments corresponding to format string fmt
	 */
	template<typename... Args>
	static void MsgBox(LPTSTR fmt, Args&&... args) {
		TCHAR szBuf[1024];

		wsprintf(szBuf, fmt, std::forward<Args>(args)...);
		::MessageBox(NULL, szBuf, TEXT(""), MB_OK);
	}

	template<Util::DebugType T>
	static void Debug(std::string msg) {
		std::string debugType;
		WORD colour = 0;
		switch (T) {
			case Util::DebugType::INFO:
				debugType = "*";
				colour = WHITE;
				break;
			case Util::DebugType::WARNING:
				debugType = "!";
				colour = LIGHT_YELLOW;
				break;
			case Util::DebugType::ADD:
				debugType = "+";
				colour = LIGHT_GREEN;
				break;
			case Util::DebugType::SUB:
				debugType = "-";
				colour = LIGHT_RED;
				break;
			case Util::DebugType::CHILD:
				debugType = ">>>";
				colour = LIGHT_BLUE;
				break;
		}

		if (T != Util::DebugType::CHILD)
			std::cout << "[";

		// change console colours
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		::GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
		::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);

		std::cout << debugType;

		// revert console colours
		::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);
		
		if (T != Util::DebugType::CHILD)
			std::cout << "]";
		std::cout << " " << msg;
	}

	template<Util::DebugType T>
	static void DebugW(std::wstring msg) {
		std::wstring debugType;
		WORD colour = 0;
		switch (T) {
			case Util::DebugType::INFO:
				debugType = L"*";
				colour = WHITE;
				break;
			case Util::DebugType::WARNING:
				debugType = L"!";
				colour = LIGHT_YELLOW;
				break;
			case Util::DebugType::ADD:
				debugType = L"+";
				colour = LIGHT_GREEN;
				break;
			case Util::DebugType::SUB:
				debugType = L"-";
				colour = LIGHT_RED;
				break;
			case Util::DebugType::CHILD:
				debugType = L">>>";
				colour = LIGHT_BLUE;
				break;
		}

		if (T != Util::DebugType::CHILD)
			std::wcout << L"[";

		// change console colours
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		::GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
		::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);

		std::wcout << debugType;

		// revert console colours
		::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);

		if (T != Util::DebugType::CHILD)
			std::wcout << L"]";
		std::wcout << L" " << msg;
	}

	static void Fatal(std::string msg) {
		Debug<Util::DebugType::SUB>(msg);
		::ExitProcess(1);
	}

	/*
	 * Utility for basic memory manipulation.
	 */
	class Memory {
		private:
			Memory() {}
			~Memory() {}
		public:
			/*
			 * Reads T-sized memory defined by generic parameter T.
			 * PARAM lpAddress : Address from which to be read
			 * RETURN : T-defined value read from lpAddress
			 */
			template<typename T>
			static T ReadMemory(LPVOID lpAddress) {
				return *((T *)lpAddress);
			}

			/*
			 * Writes T-sized memory defined by generic parameter T.
			 * PARAM lpAddress : Address to which to be written
			 */
			template<typename T>
			static void WriteMemory(LPVOID lpAddress, T value) {
				*((T *)lpAddress) = value;
			}

			template<typename T>
			T* PointMemory(DWORD address) {
				return ((T*)address);
			}

			/*
			 * Protects T-sized memory defined by generic parameter T.
			 * PARAM lpAddress : Address from which to be protected
			 * PARAM size : Size of memory to be protected
			 * PARAM flProtect : Protection type
			 * RETURN : Previous protection type
			 */
			template<typename T>
			static DWORD ProtectMemory(LPVOID lpAddress, SIZE_T size, DWORD flProtect) {
				DWORD flOldProtect = 0;
				::VirtualProtect(lpAddress, size, flProtect, &flOldProtect);

				return flOldProtect;
			}

			/*
			 * Hooks a function in the virtual table of a specified class.
			 * PARAM classInst : Instance of the class which contains the virtual table
			 * PARAM funcIndex : Index of the virtual function in the virtual table
			 * PARAM newFunc : Address of the new function
			 * RETURN : Address of the original function
			 */
			static DWORD HookVirtualFunction(DWORD classInst, DWORD funcIndex, DWORD newFunc) {
				DWORD VFTable = ReadMemory<DWORD>((LPVOID)classInst);
				DWORD hookAddress = VFTable + funcIndex * sizeof(DWORD);

				DWORD flOldProtect = ProtectMemory<DWORD>((LPVOID)hookAddress, sizeof(DWORD), PAGE_READWRITE);

				DWORD originalFunc = ReadMemory<DWORD>((LPVOID)hookAddress);
				WriteMemory<DWORD>((LPVOID)hookAddress, newFunc);

				ProtectMemory<DWORD>((LPVOID)hookAddress, sizeof(DWORD), flOldProtect);

				return originalFunc;
			}
			 /*
			  * Retrieves the address of a virtual function.
			  * PARAM classInst : Instance of the class which contains the virtual function
			  * PARAM funcIndex : Index of the cirtual function in the virtual table
			  * RETURN : Address of the function
			  */
			static DWORD GetVirtualFunction(DWORD classInst, DWORD funcIndex) {
				DWORD dwVFTable = ReadMemory<DWORD>((LPVOID)classInst);
				DWORD dwHookAddress = dwVFTable + funcIndex * sizeof(DWORD);
				return ReadMemory<DWORD>((LPVOID)dwHookAddress);
			}

			/*
			 * Hooks a function using push/ret method.
			 * PARAM dwFuncAddress : Address of the function to hook
			 * PARAM dwNewAddress : Address of the new function
			 * RETURN : Pointer to the original 6 bytes replaced by the push/ret
			 */
			static LPBYTE HookFunction(DWORD dwFuncAddress, DWORD dwNewAddress) {
				// save original bytes
				LPBYTE origBytes = new BYTE[6];
				for (int i = 0; i < 6; i++)
					origBytes[i] = ReadMemory<BYTE>((LPVOID)(dwFuncAddress + i));

				// enable write permissions
				DWORD flOldProtect = ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, PAGE_EXECUTE_READWRITE);

				// jump hook (using push/ret)
				WriteMemory<BYTE>((LPVOID)dwFuncAddress, 0x68);	// push
				WriteMemory<DWORD>((LPVOID)(dwFuncAddress + 1), dwNewAddress);
				WriteMemory<BYTE>((LPVOID)(dwFuncAddress + 5), 0xC3);	// ret

				// restore permissions
				ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, flOldProtect);

				return origBytes;
			}

			/*
			 * Unhooks a function using the push/ret method.
			 * PARAM dwFuncAddress : Address of the function to unhook
			 * PARAM origBytes : Pointer to the original 6 bytes replaced by the pust/ret
			 */
			static void UnhookFunction(DWORD dwFuncAddress, LPBYTE origBytes) {
				// enable write permissions
				DWORD flOldProtect = ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, PAGE_EXECUTE_READWRITE);

				// restore bytes
				for (int i = 0; i < 6; i++)
					WriteMemory<BYTE>((LPVOID)(dwFuncAddress + i), origBytes[i]);

				// restore permissions
				ProtectMemory<DWORD>((LPVOID)dwFuncAddress, 6, flOldProtect);
			}
	};


}

#endif // !__UTIL_H__

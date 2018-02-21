#include <iostream>
#include <string>
#include <Windows.h>

#include "hookhelper.h"
#include "Util.h"

bool APIENTRY DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			if (!::CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)initialiseHooks, nullptr, 0, nullptr))
				Util::Fatal("Failed to initialise hooks.\n");
			break;

		case DLL_PROCESS_DETACH:

			break;
	}

	return true;
}
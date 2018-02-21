#pragma once
#ifndef __HOOKHELPER_H__
#define __HOOKHELPER_H__

#include <vector>
#include <map>
#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

//
// Generic test for information on any status value.
//

#ifndef NT_INFORMATION
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#endif

//
// Generic test for warning on any status value.
//

#ifndef NT_WARNING
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#endif

//
// Generic test for error on any status value.
//

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

#define ThreadQuerySetWin32StartAddress 9

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingPositionLeft;
	ULONG StartingPositionTop;
	ULONG Width;
	ULONG Height;
	ULONG CharWidth;
	ULONG CharHeight;
	ULONG ConsoleTextAttributes;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef enum _PS_CREATE_STATE {
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, // Debugger specified
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
	SIZE_T Size;
	PS_CREATE_STATE State;
	union {
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE {
	ULONG Attribute;
	SIZE_T Size;
	union {
		ULONG Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

enum PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27
};

typedef
NTSTATUS
(NTAPI *fpNtCreateUserProcess)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
	ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
	PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
	PPS_CREATE_INFO CreateInfo,
	PPS_ATTRIBUTE_LIST AttributeList
	);

typedef
NTSTATUS
(NTAPI *fpNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

typedef
NTSTATUS
(NTAPI *fpNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef
NTSTATUS
(NTAPI *fpNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
	);

typedef
NTSTATUS
(NTAPI *fpNtGetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT Context
	);

typedef
NTSTATUS
(NTAPI *fpNtSetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT Context
	);

typedef
NTSTATUS
(NTAPI *fpNtResumeThread)(
	HANDLE ThreadHandle,
	PULONG SuspendCount
	);

typedef LONG THREADINFOCLASS;
typedef
NTSTATUS
(NTAPI *fpNtQueryInformationThread)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);

extern fpNtQueryInformationThread fNtQueryInformationThread;

extern fpNtCreateUserProcess fNtCreateUserProcess;
extern fpNtUnmapViewOfSection fNtUnmapViewOfSection;
extern fpNtAllocateVirtualMemory fNtAllocateVirtualMemory;
extern fpNtWriteVirtualMemory fNtWriteVirtualMemory;
extern fpNtGetContextThread fNtGetContextThread;
extern fpNtSetContextThread fNtSetContextThread;
extern fpNtResumeThread fNtResumeThread;

extern std::map<std::string, LPBYTE> g_originalBytes;
extern HANDLE g_hProcess; 
extern HMODULE g_hNtDll;
extern DWORD g_dwThreadId;

void initialiseHooks();
void virtualToRaw(std::vector<BYTE>& out, const std::vector<BYTE>& in);
bool dumpPe(const std::string fileName, LPVOID lpBuffer, const DWORD dwSize);

#endif // !__HOOKHELPER_H__

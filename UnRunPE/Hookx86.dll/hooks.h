#pragma once
#ifndef __HOOKS_H__
#define __HOOKS_H__

#include <Windows.h>

#include "hookhelper.h"

NTSTATUS NTAPI HookedNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
NTSTATUS NTAPI HookedNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
//NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

#endif // !__HOOKS_H__

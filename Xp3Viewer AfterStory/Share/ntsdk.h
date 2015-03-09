#ifndef NTSDK_H
#define NTSDK_H

//#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "ntdef.h"



NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);


NTSYSAPI NTSTATUS NTAPI NtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSYSAPI NTSTATUS NTAPI NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);


NTSYSAPI NTSTATUS NTAPI 
NtAllocateVirtualMemory
(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG AllocationSize, ULONG AllocationType, ULONG Protect);

NTSYSAPI NTSTATUS NTAPI
NtWriteVirtualMemory
(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI
NtReadVirtualMemory
(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI
NtFreeVirtualMemory
(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG FreeSize, ULONG FreeType);



NTSYSAPI NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);


NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER Interval);


NTSYSAPI NTSTATUS NTAPI 
LdrLoadDll
(
IN PWCHAR PathToFile OPTIONAL,
IN ULONG Flags OPTIONAL,
IN PUNICODE_STRING ModuleFileName,
OUT PHANDLE ModuleHandle
);


NTSYSAPI NTSTATUS NTAPI  RtlGetFullPathName_U(WCHAR *dosname, ULONG size, WCHAR *buf, WCHAR **shortname);

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE Handle);




#ifdef __cplusplus
}
#endif






#endif
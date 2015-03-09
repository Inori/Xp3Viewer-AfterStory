#include <Windows.h>
#include "../Share/ntsdk.h"

BYTE ShellCode[] =
{
	0x50,//									push    eax;						eax = 0x00401000
	0x60,//									pushad
	0x9C,//									pushfd
	0xE8, 0x00,0x00, 0x00, 0x00,//			call    $+5
	0x5E,//									pop     esi;						即此条指令地址弹出到esi
	0x81, 0xE6, 0x00, 0xF0, 0xFF, 0xFF,//	and     esi, 0xFFFFF000;			空间首地址，即BaseAddress
	0xAD,//									lods    dword ptr[esi];				初始eip(即RtlUserThreadStart)存至eax
	0x89, 0x44, 0x24, 0x24,//				mov     dword ptr[esp + 0x24], eax;	后面popad弹出到eip
	0xAD,//									lods    dword ptr[esi];				LdrLoadDll地址
	0x33, 0xC9,//							xor     ecx, ecx
	0x51,//									push    ecx
	0x56,//									push    esi
	0x51,//									push    ecx
	0x51,//									push    ecx
	0xFF, 0xD0,//							call    eax
	0x58,//									pop     eax
	0x96,//									xchg    eax, esi
	0x25, 0x00, 0xF0, 0xFF, 0xFF,//			and     eax, 0xFFFFF000
	0x83, 0x20, 0x9D,//						and     dword ptr[eax], 0xFFFFFF9D
	0x61,//									popad
	0xC3//									retn
};


INT CalcInterval(PLARGE_INTEGER pInterval, UINT n) //不知道什么用途
{
	int Result;

	if (n == -1)
	{
		*(DWORD*)pInterval = 0;
		*(DWORD*)(pInterval + 4) = 0x80000000;
		Result = (int)pInterval;
	}
	else
	{
		*(QWORD *)pInterval = -10000i64 * n;
		Result = (int)pInterval;
	}
	return Result;
}

NTSTATUS InjectDllToRemoteProcess(HANDLE hProcess, HANDLE hThread, PUNICODE_STRING DllFullPath)
{

	HANDLE ProcessHandle;
	HANDLE ThreadHandle;
	
	ULONG DllPathLength; 

	NTSTATUS Status; 
	NTSTATUS Result;

	signed int v11; 

	PVOID BaseAddress; //VirtualMemory地址
	ULONG VMSize; //VirtualMemory大小
	ULONG FreeSize;

	PVOID pShellCode;
	ULONG CodeLength;

	ULONG ReturnedLength;
	//以下5个变量将拷贝到目标进程地址空间，声明顺序不可改变

#pragma pack(1)	//这里没搞懂怎么取消变量对齐，以及如何避免Release版中把这几个变量优化掉到问题
	DWORD Eip;
	PVOID LdrLoadDllAddr;
	SHORT DllPathLength1;
	SHORT DllPathLength2;
	CHAR *DllPathVMAddr; //DllFullPath 在 VirtualMemory 中的地址
#pragma pack()

	LARGE_INTEGER Interval;
	CONTEXT Context; 

	ThreadHandle = hThread;
	ProcessHandle = hProcess;

	Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; //65539
	Result = NtGetContextThread(hThread, &Context);

	if (NT_SUCCESS(Result))
	{
		BaseAddress = 0;
		VMSize = 0x1000;
		Result = NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &VMSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (NT_SUCCESS(Result))
		{
			DllPathLength = *(WORD*)DllFullPath;

			pShellCode = (void*)ShellCode;
			CodeLength = sizeof(ShellCode);
			LdrLoadDllAddr = LdrLoadDll;
			Eip = Context.Eip;
			DllPathVMAddr = (char*)BaseAddress + 16;

			DllPathLength1 = DllPathLength;
			DllPathLength2 = DllPathLength;

			FreeSize = 0;

			Status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, &Eip, 16, &ReturnedLength);
			if (NT_SUCCESS(Status))
			{
				Status = NtWriteVirtualMemory(ProcessHandle, (char*)BaseAddress + 16, *(PVOID*)((char*)DllFullPath + 4), DllPathLength, &ReturnedLength);
				if (NT_SUCCESS(Status))
				{
					Context.Eip = (DWORD)((char*)BaseAddress + DllPathLength + 31) & 0xFFFFFFF0;
					Status = NtWriteVirtualMemory(ProcessHandle, (PVOID)((DWORD)((char *)BaseAddress + DllPathLength + 31) & 0xFFFFFFF0), ShellCode, CodeLength, &ReturnedLength);
					if (NT_SUCCESS(Status))
					{
						Status = NtSetContextThread(ThreadHandle, &Context);
						if (NT_SUCCESS(Status))
						{
							NtGetContextThread(ThreadHandle, &Context);
							Status = NtResumeThread(ThreadHandle, NULL);
							if (NT_SUCCESS(Status))
							{
								CalcInterval(&Interval, 500);
								v11 = 30;
								
								while (1)
								{
									Status = NtReadVirtualMemory(ProcessHandle, BaseAddress, &ShellCode, 4, &ReturnedLength);
									if (!NT_SUCCESS(Status))
										break;
									if (pShellCode)
									{
										NtDelayExecution(0, &Interval);
										--v11;
										if (v11)
											continue;
									}

									NtDelayExecution(0, &Interval);
									Status = NtGetContextThread(ThreadHandle, &Context);
									if (!NT_SUCCESS(Status))
										break;

									if ((PVOID)Context.Eip < BaseAddress || (PVOID)Context.Eip > (char*)BaseAddress + VMSize)
									{									
										NtFreeVirtualMemory(ProcessHandle, &BaseAddress, &FreeSize, MEM_RELEASE);
										Result = STATUS_SUCCESS;
									}
									else
									{
										NtFreeVirtualMemory(ProcessHandle, &BaseAddress, &FreeSize, MEM_RELEASE);
										Result = STATUS_UNSUCCESSFUL;
									}
									return Result;
								}
							}
						}
					}
				}
			}
			NtFreeVirtualMemory(ProcessHandle, &BaseAddress, &FreeSize, MEM_RELEASE);
			Result = Status;
		}
	}
	return Result;
}


typedef BOOL(NTAPI *fnCreateProcessInternalW)
(
HANDLE hToken,
PCWSTR lpApplicationName,
PCWSTR lpCommandLine,
LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes, 
BOOL bInheritHandles, 
DWORD dwCreationFlags, 
LPVOID lpEnvironment,
PCWSTR lpCurrentDirectory, 
LPSTARTUPINFOW lpStartupInfo,
LPPROCESS_INFORMATION lpProcessInformation, 
PHANDLE phNewToken
);

fnCreateProcessInternalW CreateProcessInternalW;

VOID InitAPIAddress()
{
	CreateProcessInternalW = (fnCreateProcessInternalW)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessInternalW");
}


ULONG Nt_GetExeDirectory(WCHAR* FullPath, ULONG WstrLen)
{
	ULONG i;
	ULONG DirectoryLength;
	
	for (i = WstrLen; i != 0; i--)
	{
		WCHAR wc = *(FullPath + i - 1);
		if (wc == L'\\' || wc == L'/')
			break;
	}

	if (i == WstrLen)
		return WstrLen;

	if (i == 0)
		return 0;

	FullPath[i] = L'\0';
	DirectoryLength = i;

	return DirectoryLength;
}

int __cdecl main(int argc, char *argv[])
{
	
	NTSTATUS            Status;
	BOOLEAN				IsEnabled;
	WCHAR               ExePath[MAX_NTPATH], szDllPath[MAX_NTPATH], FullExePath[MAX_NTPATH];
	STARTUPINFOW        si;
	PROCESS_INFORMATION pi;
	
	if (argc == 1)
		return -1;

	InitAPIAddress();

	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &IsEnabled);
	while (--argc)
	{
		wcscpy(ExePath, L"LOVESICK_PUPPIES.exe");
		/*
		pExePath = findextw(*++argv);
		if (CHAR_UPPER4W(*(PULONG64)pExePath) == CHAR_UPPER4W(TAG4W('.LNK')))
		{
			if (FAILED(GetPathFromLinkFile(*argv, FullExePath, countof(FullExePath))))
			{
				pExePath = *argv;
			}
			else
			{
				pExePath = FullExePath;
			}
		}
		else
		{
			pExePath = *argv;
		}
		*/
		RtlGetFullPathName_U(ExePath, sizeof(szDllPath), szDllPath, NULL);

		//rmnamew(szDllPath);
		Nt_GetExeDirectory(szDllPath, wcslen(szDllPath));
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		Status = CreateProcessInternalW(
			NULL,
			ExePath,
			NULL,
			NULL,
			NULL,
			FALSE,
			CREATE_SUSPENDED,
			NULL,
			*szDllPath == 0 ? NULL : szDllPath,
			&si,
			&pi,
			NULL);

		if (!Status)
		{
			//PrintConsoleW(L"%s: CreateProcess() failed\n", pExePath);
			continue;
		}

		ULONG Length;
		UNICODE_STRING DllFullPath;

		Length = Nt_GetExeDirectory(szDllPath, wcslen(szDllPath));
		wcscpy(szDllPath + Length, L"XP3Viewer.dll");
		DllFullPath.Buffer = szDllPath;
		DllFullPath.Length = (USHORT)(Length + wcslen(L"XP3Viewer.dll"));
		DllFullPath.Length *= sizeof(WCHAR);
		DllFullPath.MaximumLength = DllFullPath.Length;

		Status = InjectDllToRemoteProcess(pi.hProcess, pi.hThread, &DllFullPath);

		if (!NT_SUCCESS(Status))
		{
			//            PrintError(GetLastError());
			NtTerminateProcess(pi.hProcess, 0);
		}

		NtClose(pi.hProcess);
		NtClose(pi.hThread);
	}
	
	return Status;
}
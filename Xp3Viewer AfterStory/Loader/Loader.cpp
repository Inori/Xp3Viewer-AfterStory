#include <Windows.h>
#include <shlobj.h>
#include "../Share/ntsdk.h"

#pragma pack(1)
//目标地址空间执行ShellCode时所需的参数
//以下5个变量将拷贝到目标进程地址空间，声明顺序不可改变
typedef struct _VM_PARAMETER
{
	DWORD Eip;
	PVOID LdrLoadDllAddr;
	SHORT DllPathLength1;
	SHORT DllPathLength2;
	CHAR *DllPathVMAddr; //DllFullPath 在 VirtualMemory 中的地址
}VM_PARAMETER;

#pragma pack()

BYTE ShellCode[] =
{
	//0xcc,//									int3;								用于调试
	0x50,//									push    eax;						eax = oep
	0x60,//									pushad
	0x9C,//									pushfd
	0xE8, 0x00,0x00, 0x00, 0x00,//			call    $+5
	0x5E,//									pop     esi;						即此条指令地址弹出到esi
	0x81, 0xE6, 0x00, 0xF0, 0xFF, 0xFF,//	and     esi, 0xFFFFF000;			空间首地址，即BaseAddress
	0xAD,//									lods    dword ptr[esi];				初始eip(即RtlUserThreadStart)存至eax
	0x89, 0x44, 0x24, 0x24,//				mov     dword ptr[esp + 0x24], eax;	后面popad弹出
	0xAD,//									lods    dword ptr[esi];				LdrLoadDll地址
	0x33, 0xC9,//							xor     ecx, ecx
	0x51,//									push    ecx
	0x54,//									push    esp
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


INT SetInterval(PLARGE_INTEGER pInterval, UINT n) //转换时间间隔
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
		*(QWORD*)pInterval = -10000i64 * n;
		Result = (int)pInterval;
	}
	return Result;
}

NTSTATUS InjectDllToRemoteProcess(HANDLE hProcess, HANDLE hThread, PUNICODE_STRING DllFullPath)
{

	HANDLE ProcessHandle;
	HANDLE ThreadHandle;
	
	volatile ULONG DllPathLength; 

	NTSTATUS Status; 
	NTSTATUS Result;

	signed int Delay; 

	PVOID BaseAddress; //VirtualMemory地址
	ULONG VMSize; //VirtualMemory大小
	
	PVOID pShellCode;
	ULONG CodeLength;

	VM_PARAMETER VmPara;

	LARGE_INTEGER Interval;
	CONTEXT Context; 

	ULONG ReturnedLength;
	ULONG FreeSize;

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

			VmPara.Eip = Context.Eip;
			VmPara.LdrLoadDllAddr = LdrLoadDll;	
			VmPara.DllPathLength1 = DllPathLength;
			VmPara.DllPathLength2 = DllPathLength;
			VmPara.DllPathVMAddr = (char*)BaseAddress + sizeof(VM_PARAMETER);

			FreeSize = 0;//无实际用途
			
			//写参数
			Status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, (PVOID)&VmPara, sizeof(VM_PARAMETER), &ReturnedLength); //将栈中Eip开始的sizeof(VM_PARAMETER)个字节拷贝到目标地址空间
			if (NT_SUCCESS(Status))
			{
				//写Dll路径
				Status = NtWriteVirtualMemory(ProcessHandle, (char*)BaseAddress + sizeof(VM_PARAMETER), *(PVOID*)((char*)DllFullPath + 4), DllPathLength, &ReturnedLength);
				if (NT_SUCCESS(Status))
				{
					Context.Eip = (DWORD)((char*)BaseAddress + DllPathLength + sizeof(VM_PARAMETER));
					//写ShellCode
					Status = NtWriteVirtualMemory(ProcessHandle, (PVOID)((DWORD)((char*)BaseAddress + DllPathLength + sizeof(VM_PARAMETER))), pShellCode, CodeLength, &ReturnedLength);
					if (NT_SUCCESS(Status))
					{
						Status = NtSetContextThread(ThreadHandle, &Context);
						if (NT_SUCCESS(Status))
						{
							NtGetContextThread(ThreadHandle, &Context);
							Status = NtResumeThread(ThreadHandle, NULL); //恢复线程以执行ShellCode
							
							if (NT_SUCCESS(Status))
							{
								SetInterval(&Interval, 500);
								Delay = 5; //等待的循环次数
								
								while (1)
								{
									Status = NtReadVirtualMemory(ProcessHandle, BaseAddress, &pShellCode, 4, &ReturnedLength);
									if (!NT_SUCCESS(Status))
										break;
									if (pShellCode)
									{
										NtDelayExecution(0, &Interval);
										--Delay;
										if (Delay)
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


ULONG GetExeDirectory(WCHAR* FullPath, ULONG WstrLen)
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

PWCHAR GetBaseName(PWCHAR FullName)
{
	ULONG i;
	ULONG WstrLen = wcslen(FullName);

	for (i = WstrLen; i != 0; i--)
	{
		WCHAR wc = *(FullName + i - 1);
		if (wc == L'\\' || wc == L'/')
			break;
	}

	if (i == WstrLen)
		return NULL;
	if (i == 0)
		return FullName;

	return &FullName[i];
}

BOOL GetPathFromLinkFile(WCHAR* ShortcutFile, WCHAR* buffer, int nSize)
{
	HRESULT           hres;
	IShellLink        *psl;
	IPersistFile      *ppf;
	WIN32_FIND_DATA   fd;

	CoInitialize(NULL);
	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&psl);
	if (!SUCCEEDED(hres))
		return false;

	hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
	if (SUCCEEDED(hres))
	{
		hres = ppf->Load(ShortcutFile, STGM_READ);
		if (SUCCEEDED(hres))
			//hres = psl->GetPath(buffer, nSize, &fd, 0); //??
		ppf->Release();
	}

	psl->Release();
	CoUninitialize();
	return SUCCEEDED(hres);
}

int __cdecl main(int argc, wchar_t* argv[])
{
	
	NTSTATUS            Status;
	BOOLEAN				IsEnabled;
	WCHAR               *pExePath, szDllPath[MAX_NTPATH], FullExePath[MAX_NTPATH];
	STARTUPINFOW        si;
	PROCESS_INFORMATION pi;
	
	if (argc == 1)
		return -1;

	InitAPIAddress();

	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &IsEnabled);
	while (--argc)
	{
		pExePath = GetBaseName(*++argv);
		if (wcsstr(pExePath, L".LNK") || wcsstr(pExePath, L".lnk"))
		{
			if (FAILED(GetPathFromLinkFile(*argv, FullExePath, wcslen(FullExePath))))
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
		
		RtlGetFullPathName_U(pExePath, sizeof(szDllPath), szDllPath, NULL);

		GetExeDirectory(szDllPath, wcslen(szDllPath));
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		Status = CreateProcessInternalW(
			NULL,
			pExePath,
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

		Length = GetExeDirectory(szDllPath, wcslen(szDllPath));
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
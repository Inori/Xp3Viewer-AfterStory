#ifndef NTDEF_H
#define NTDEF_H

#if _MSC_VER > 1000
#pragma once
#endif

//#include <ctype.h>  // winnt ntndis

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

#ifndef NOTHING
#define NOTHING
#endif

#ifndef CRITICAL
#define CRITICAL
#endif

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1       // winnt
#endif



#ifndef CONST
#define CONST               const
#endif

//
// Basics
//

#ifndef VOID
#define VOID void
#endif

typedef char CHAR;
typedef unsigned char UCHAR;
typedef unsigned char BYTE;

typedef short SHORT;
typedef unsigned short USHORT;
typedef unsigned short WORD;

typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long DWORD;

typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;
typedef unsigned __int64 QWORD;

#if !defined(MIDL_PASS)
typedef int INT;
#endif



typedef LONG NTSTATUS, *PNTSTATUS, **PPNTSTATUS;

#define STATUS_SUCCESS                      ((NTSTATUS) 0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH         ((NTSTATUS) 0xC0000004)
#define STATUS_IO_DEVICE_ERROR              ((NTSTATUS) 0xC0000185)
#define STATUS_UNSUCCESSFUL					((NTSTATUS) 0xC0000001)


#define MAX_NTPATH 260


//
// Generic status value.
//
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

//
//String
//

typedef struct _UNICODE_STRING
{
	WORD  Length;
	WORD  MaximumLength;
	PWSTR Buffer;
}UNICODE_STRING, *PUNICODE_STRING, **PPUNICODE_STRING;

#define UNICODE_STRING_LENGTH sizeof(UNICODE_STRING)




//
//Privileges
//
#define SE_BACKUP_PRIVILEGE		0x11
#define SE_RESTORE_PRIVILEGE	0x12
#define SE_SHUTDOWN_PRIVILEGE	0x13     //关机权限
#define SE_DEBUG_PRIVILEGE		0x14     //调试权限


#endif //NTDEF_H
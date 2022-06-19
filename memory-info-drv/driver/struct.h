#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <IntSafe.h>
#include <ntimage.h>
#include <windef.h>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <intrin.h>

//
// User Kernel mode struct
//
typedef struct DriverControl {
	UINT32 rqstType;
	HANDLE pId;

	struct AllocateVMM {
		PVOID base;
		PVOID information;
		PVOID buffer;
		SIZE_T size;
		ULONG aType;
		ULONG protect;
	} AllocateVM;
	struct QueryInforamtion {
		MEMORY_BASIC_INFORMATION mbi;
		PVOID  base;
		SIZE_T returnLength;
	}QueryInforamtion;
	struct ReadMem {
		PVOID  base;
		PVOID  buffer;
		SIZE_T size;
	}Read;
	struct MemoryMem {
		PVOID src;
		PVOID dst;
		SIZE_T size;
		SIZE_T retSize;
	}Write;
	struct ChangeProtect {
		PVOID address;
		DWORD protect;
		SIZE_T size;
		DWORD oldProtect;
	}ChangeProtect;
	struct GetHandle {
		HANDLE pHandle;
	}GetHandle;
}*PDIVERCONTROLL;

//------------------------------------------------------------------------------------------


//
// Rqst Types
//
typedef enum RqstTypes {
	WRITE,
	READ,
	ALLOCATE,
	CHANGE_PROTECT,
	QUERY_INFO,
	GET_HANDLE,
}RqstTypes_t;
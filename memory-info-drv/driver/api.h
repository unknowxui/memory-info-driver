#pragma once
#include "imports.h"

#include "defs.h"


//
// Write virtual memory 
//
static 
void 
write( HANDLE pId, PVOID src, PVOID dst, SIZE_T srcSize, SIZE_T dstSize ) {
    PEPROCESS eProcess = 0;

    PsLookupProcessByProcessId( pId, &eProcess );
    if ( eProcess == NULL ) {
        log( "Error PsLookupProcessByProcessId in Write ! \n" );
        return;
    }
    log( "write to -> %p size -> %i  buffer -> %p\n", src, srcSize, dst );

    NTSTATUS status = MmCopyVirtualMemory( PsGetCurrentProcess(),
        src,
        eProcess,
        dst, srcSize,
        KernelMode,
        &dstSize );
    if ( !NT_SUCCESS( status ) ) {
        log( "Error MmCopyVirtualMemory ! %p\n", status );
        return;
    }

    ObDereferenceObject( eProcess );
}


//
// Change protect virtual memory
//
static
void
change_protect( HANDLE pId, PVOID address, SIZE_T size, DWORD protect, DWORD oldProt ) {
    PEPROCESS eProcess = 0;
    KAPC_STATE apc = { 0 };
    NTSTATUS status = 0;

    status = PsLookupProcessByProcessId( pId, &eProcess );
    if ( !NT_SUCCESS( status ) || eProcess == NULL ) {
        log( "Error PsLookupProcess status = %p \n", status );
        return;
    }

    KeStackAttachProcess( eProcess, &apc );

    status = ZwProtectVirtualMemory( ZwCurrentProcess(),
        &address,
        &size,
        protect,
        &oldProt );
    if ( !NT_SUCCESS( status ) ) {
        log( "Error ZwProtectVM status = %p \n", status );
        return;
    }
    log( "ZwProtectVM status -> %p \n", status );
    KeUnstackDetachProcess( &apc );
    ObDereferenceObject( eProcess );
}

//
// Read virtual Memory
//
static 
PVOID
read( HANDLE pId, PVOID base, PVOID buffer, SIZE_T size ) {
    PEPROCESS eProcess = 0;

    PsLookupProcessByProcessId( pId, &eProcess );
    if ( eProcess == NULL ) {
        log( "Error PsLookupProcessByProcessId in Write ! \n" );
        return;
    }
    NTSTATUS status = MmCopyVirtualMemory( eProcess,
        base,
        PsGetCurrentProcess(),
        buffer, size,
        KernelMode,
        &size );
    if ( !NT_SUCCESS( status ) ) {

        log( "Error MmCopyVirtualMemory ! %p \n", status );
        return;
    }

    ObDereferenceObject( eProcess );
}

//
// Alloc virtual memory
// 
static 
PVOID
allocate_vm( HANDLE pId, PVOID base, SIZE_T allocSize, ULONG type, ULONG protect ) {
    KAPC_STATE sApc = { 0 };
    PEPROCESS  eProcess = NULL;

    PsLookupProcessByProcessId( pId, &eProcess );
    if ( eProcess == NULL ) {
        return NULL;
    }
    KeStackAttachProcess( eProcess, &sApc );

    log( "ZwAllocateVirtualMemory: base %p allocSize %i type %i protect %i \n", base, allocSize, type, protect );
    if ( !NT_SUCCESS( ZwAllocateVirtualMemory( ZwCurrentProcess(), &base, NULL, &allocSize, type, protect ) ) ) {
        log( "Error ZeAllocateVm ! \n" );
        KeUnstackDetachProcess( &sApc );
        ObDereferenceObject( eProcess );
        return NULL;
    }

    KeUnstackDetachProcess( &sApc );
    ObDereferenceObject( eProcess );

    return base;
}

// 
// Free allocate virtual memory
//
static 
NTSTATUS
free_vm( HANDLE pId, PVOID base, SIZE_T size, ULONG type ) {
    KAPC_STATE apc = { NULL };
    PEPROCESS eProcess = NULL;

    PsLookupProcessByProcessId( pId, &eProcess );
    if ( eProcess = NULL ) {
        log( "Error PsLookupProcessById \n" );
        return STATUS_ABANDONED;
    }

    KeStackAttachProcess( eProcess, &apc );

    if ( !NT_SUCCESS( ZwFreeVirtualMemory( PsGetCurrentProcess(), &base, &size, type ) ) ) {
        log( "Error ZeFreeVirtualMemory ! \n" );
        return STATUS_SUCCESS;
    }

    KeUnstackDetachProcess( &apc );
    ObDereferenceObject( eProcess );
}

//
// Get process handle by pId
//
static 
HANDLE 
get_process_handle(HANDLE pId) {
    HANDLE     hProcess;
    OBJECT_ATTRIBUTES oaAttributes = { sizeof( OBJECT_ATTRIBUTES ) };
    CLIENT_ID cidProcess;
    cidProcess.UniqueProcess = pId;
    cidProcess.UniqueThread = 0;

    NTSTATUS status = ZwOpenProcess( &hProcess, PROCESS_ALL_ACCESS, &oaAttributes, &cidProcess );
    if ( !NT_SUCCESS( status ) ) {
        log( "ZwOpenProcess error status = %p \n", status );
    }

    return hProcess;
}


//
// Write readonly memory 
//
static
void  
write_read_only_memory( PVOID dst, PVOID src, SIZE_T size ) {
    PMDL mdl = IoAllocateMdl( dst, ( ULONG )size, FALSE, FALSE, NULL );

    if ( !mdl )
        return;

    MmProbeAndLockPages( mdl, KernelMode, IoReadAccess );
    PVOID mapping = MmMapLockedPagesSpecifyCache( mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority );
    MmProtectMdlSystemAddress( mdl, PAGE_READWRITE );

    RtlCopyMemory( mapping, src, size );

    MmUnmapLockedPages( mapping, mdl );
    MmUnlockPages( mdl );
    IoFreeMdl( mdl );
}

// 
// This two function for get export function address
// 
PVOID get_system_module_base( const char* module_name ) {
    ULONG bytes = 0;
    NTSTATUS status = ZwQuerySystemInformation( SystemModuleInformation, 0, bytes, &bytes );

    if ( !bytes )
        return 0;

    PRTL_PROCESS_MODULES modules = ( PRTL_PROCESS_MODULES )ExAllocatePoolWithTag( NonPagedPool, bytes, 0x454E4F45 ); // 'ENON'

    status = ZwQuerySystemInformation( SystemModuleInformation, modules, bytes, &bytes );

    if ( !NT_SUCCESS( status ) )
        return 0;

    PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
    PVOID module_base = 0, module_size = 0;

    for ( ULONG i = 0; i < modules->NumberOfModules; i++ ) {
        if ( strcmp( ( char* )module[i].FullPathName, module_name ) == 0 ) {
            module_base = module[i].ImageBase;
            module_size = ( PVOID )module[i].ImageSize;
            break;
        }
    }

    if ( modules )
        ExFreePoolWithTag( modules, 0 );

    if ( module_base <= 0 )
        return 0;

    return module_base;
}
PVOID get_system_module_export( const char* module_name, LPCSTR routine_name ) {
    PVOID lpModule = get_system_module_base( module_name );

    if ( !lpModule )
        return NULL;

    return RtlFindExportedRoutineByName( lpModule, routine_name );
}

//
// Memory basic information 
//
static 
MEMORY_BASIC_INFORMATION 
query_inforamtionF( HANDLE pId, MEMORY_BASIC_INFORMATION mbi, PVOID base, SIZE_T retLen ) {
    PEPROCESS                eProcess = { 0 };
    KAPC_STATE               apc = { 0 };

    PsLookupProcessByProcessId( pId, &eProcess );
    if ( eProcess == NULL ) {
        log( "Error PsLookupProcessByProcessId ! \n" );
        return mbi;
    }

    KeStackAttachProcess( eProcess, &apc );

    if ( !NT_SUCCESS( ZwQueryVirtualMemory( ZwCurrentProcess(), base, MemoryBasicInformation, &mbi, sizeof( MEMORY_BASIC_INFORMATION ), &retLen ) ) ) {
        log( "Error QueryInformation ! \n" );
        return mbi;
    }

    KeUnstackDetachProcess( &apc );
    ObDereferenceObject( eProcess );

    return mbi;
}

//
// Allocate virtual memory
//
static
PVOID 
allocate_memory( HANDLE pId, PVOID base, SIZE_T allocSize, ULONG type, ULONG protect ) {
    KAPC_STATE sApc = { 0 };
    PEPROCESS  eProcess = NULL;

    PsLookupProcessByProcessId( pId, &eProcess );
    if ( eProcess == NULL ) {
        return NULL;
    }
    KeStackAttachProcess( eProcess, &sApc );

    log( "ZwAllocateVirtualMemory: base %p allocSize %i type %i protect %i \n", base, allocSize, type, protect );
    if ( !NT_SUCCESS( ZwAllocateVirtualMemory( ZwCurrentProcess(), &base, NULL, &allocSize, type, protect ) ) ) {
        log( "Error ZeAllocateVm ! \n" );
        KeUnstackDetachProcess( &sApc );
        ObDereferenceObject( eProcess );
        return NULL;
    }

    KeUnstackDetachProcess( &sApc );
    ObDereferenceObject( eProcess );

    return base;
}
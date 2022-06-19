#include "driver/struct.h"

#include "driver/api.h"

//
// Hook handler
//
NTSTATUS hook_handler( PVOID param ) {
	PDIVERCONTROLL control = ( PDIVERCONTROLL )(param);

	log( "Hook be call ! \n" );

	switch ( control->rqstType ) {
		case WRITE:
		{
			log( "Write ! \n" );

			write( control->pId, control->Write.dst, control->Write.src, control->Write.size, control->Write.retSize );
			break;
		}
		case GET_HANDLE:
		{
			log( "Get handle ! \n" );

			control->GetHandle.pHandle = get_process_handle( control->pId );

			break;
		}
		case READ:
		{
			log( "Read memory ! \n" );

			control->Read.buffer = read( control->pId, control->Read.base, control->Read.buffer, control->Read.size );
			break;
		}
		case CHANGE_PROTECT:
		{
			log( "Change Protect ! \n" );
			change_protect( 
				control->pId, 
				control->ChangeProtect.address, 
				control->ChangeProtect.size, 
				control->ChangeProtect.protect, 
				control->ChangeProtect.oldProtect );

			break;
		}
		case QUERY_INFO:
		{
			log( "Memory basic information ! \n" );

			control->QueryInforamtion.mbi = query_inforamtionF( 
				control->pId, 
				control->QueryInforamtion.mbi, 
				control->QueryInforamtion.base, 
				control->QueryInforamtion.returnLength );

			break;
		}
		case ALLOCATE:
		{
			log( "Allocate VM ! \n" );

			control->AllocateVM.base = allocate_memory( control->pId, 
				control->AllocateVM.base, 
				control->AllocateVM.size, 
				control->AllocateVM.aType, 
				control->AllocateVM.protect );

			break;
		}
	}

	return STATUS_SUCCESS;
}


// 
// Custom entry point
//
NTSTATUS entry( PVOID a, PVOID b) {

	log( "Fucking entry point ! \n" );

	PVOID dxgk_routine
		= ( PVOID )(get_system_module_export( "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtOpenCompositionSurfaceSectionInfo" ));

	if ( !dxgk_routine ) {
		return 0;
	}

	BYTE dxgk_original[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x18, 0x4D, 0x89, 0x4B, 0x20, 0x49, 0x89, 0x4B, 0x08 };

	BYTE shell_code_start[] =
	{
		0x48, 0xB8
	};

	BYTE shell_code_end[] =
	{
		0xFF, 0xE0,
		0xCC
	};

	RtlSecureZeroMemory( &dxgk_original, sizeof( dxgk_original ) );
	memcpy( ( PVOID )(( ULONG_PTR )dxgk_original), &shell_code_start, sizeof( shell_code_start ) );
	uintptr_t test_address = ( uintptr_t )(&hook_handler);
	memcpy( ( PVOID )(( ULONG_PTR )dxgk_original + sizeof( shell_code_start )), &test_address, sizeof( void* ) );
	memcpy( ( PVOID )(( ULONG_PTR )dxgk_original + sizeof( shell_code_start ) + sizeof( void* )), &shell_code_end, sizeof( shell_code_end ) );
	write_read_only_memory( dxgk_routine, &dxgk_original, sizeof( dxgk_original ) );

	return STATUS_SUCCESS;
}
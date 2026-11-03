#pragma once

// ── Compile-time XOR string encryption ───────────────────────
// ซ่อน string literals — strings.exe / FLOSS / Detect-It-Easy ไม่เห็น
// เปลี่ยน XK เป็น key ของตัวเอง (1 byte, ไม่เป็น 0x00)
#define XK 0xAB

// encrypt ตอน compile (compiler fold เป็น constant)
// ใช้ได้กับ string ยาวสุด 64 ตัว — ขยาย _XB ถ้าต้องการยาวกว่า
#define _XB(s,i) ((i)<sizeof(s)-1?(char)((unsigned char)(s)[i]^(XK)):0)

#define XS8(s)  (char[]){_XB(s,0),_XB(s,1),_XB(s,2),_XB(s,3),_XB(s,4),_XB(s,5),_XB(s,6),_XB(s,7),0}
#define XS16(s) (char[]){_XB(s,0),_XB(s,1),_XB(s,2),_XB(s,3),_XB(s,4),_XB(s,5),_XB(s,6),_XB(s,7),_XB(s,8),_XB(s,9),_XB(s,10),_XB(s,11),_XB(s,12),_XB(s,13),_XB(s,14),_XB(s,15),0}
#define XS32(s) (char[]){_XB(s,0),_XB(s,1),_XB(s,2),_XB(s,3),_XB(s,4),_XB(s,5),_XB(s,6),_XB(s,7),_XB(s,8),_XB(s,9),_XB(s,10),_XB(s,11),_XB(s,12),_XB(s,13),_XB(s,14),_XB(s,15),_XB(s,16),_XB(s,17),_XB(s,18),_XB(s,19),_XB(s,20),_XB(s,21),_XB(s,22),_XB(s,23),_XB(s,24),_XB(s,25),_XB(s,26),_XB(s,27),_XB(s,28),_XB(s,29),_XB(s,30),_XB(s,31),0}
#define XS64(s) (char[]){_XB(s,0),_XB(s,1),_XB(s,2),_XB(s,3),_XB(s,4),_XB(s,5),_XB(s,6),_XB(s,7),_XB(s,8),_XB(s,9),_XB(s,10),_XB(s,11),_XB(s,12),_XB(s,13),_XB(s,14),_XB(s,15),_XB(s,16),_XB(s,17),_XB(s,18),_XB(s,19),_XB(s,20),_XB(s,21),_XB(s,22),_XB(s,23),_XB(s,24),_XB(s,25),_XB(s,26),_XB(s,27),_XB(s,28),_XB(s,29),_XB(s,30),_XB(s,31),_XB(s,32),_XB(s,33),_XB(s,34),_XB(s,35),_XB(s,36),_XB(s,37),_XB(s,38),_XB(s,39),_XB(s,40),_XB(s,41),_XB(s,42),_XB(s,43),_XB(s,44),_XB(s,45),_XB(s,46),_XB(s,47),_XB(s,48),_XB(s,49),_XB(s,50),_XB(s,51),_XB(s,52),_XB(s,53),_XB(s,54),_XB(s,55),_XB(s,56),_XB(s,57),_XB(s,58),_XB(s,59),_XB(s,60),_XB(s,61),_XB(s,62),_XB(s,63),0}

// auto-select macro by string length
#define XS(s) ( \
    sizeof(s)<=9  ? XS8(s)  : \
    sizeof(s)<=17 ? XS16(s) : \
    sizeof(s)<=33 ? XS32(s) : \
                    XS64(s) )

// decrypt in-place ตอน runtime
static __inline void xdec(char*s){for(int i=0;s[i];i++)s[i]^=XK;}

// ── helper: decrypt + use + zero ─────────────────────────────
// ตัวอย่าง:
//   XUSE(cmd, "taskkill /f /im explorer.exe", system(cmd));
#define XUSE(var,lit,expr) do{ char var[]=XS(lit); xdec(var); expr; memset(var,0,sizeof(var)); }while(0)

// ── ตัวอย่างการใช้ ────────────────────────────────────────────
// แบบเดิม (อ่านได้ทันที):
//   system("taskkill /f /im explorer.exe");
//
// แบบซ่อน:
//   XUSE(cmd, "taskkill /f /im explorer.exe", system(cmd));
//
// หรือแบบ manual:
//   char s[] = XS("regedit.exe");
//   xdec(s);
//   // ใช้ s
//   memset(s, 0, sizeof(s));

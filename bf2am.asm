; bf2am - bf2 auto admin over rcon, x86-64 linux, no libc
bits 64
default abs

%include "md5tab.inc"

section .bss
block:    resb 64
digest:   resb 16
hexbuf:   resb 40

section .data
hexchars: db "0123456789abcdef"
nl:       db 10

section .text
global _start

; rdi = msg, rsi = len (<= 55). result in digest
md5:
    push rbx
    push rdi
    push rsi
    lea rdi, [block]
    mov ecx, 64
    xor eax, eax
    rep stosb
    pop rcx
    pop rsi
    push rcx
    lea rdi, [block]
    rep movsb
    pop rcx
    mov byte [block+rcx], 0x80
    shl rcx, 3
    mov [block+56], rcx
    mov r8d, 0x67452301
    mov r9d, 0xefcdab89
    mov r10d, 0x98badcfe
    mov r11d, 0x10325476
    xor ebx, ebx
.round:
    cmp ebx, 16
    jb .r1
    cmp ebx, 32
    jb .r2
    cmp ebx, 48
    jb .r3
    mov esi, r11d
    not esi
    or esi, r9d
    xor esi, r10d
    lea eax, [rbx*8]
    sub eax, ebx
    and eax, 15
    jmp .go
.r1:
    mov esi, r9d
    and esi, r10d
    mov edi, r9d
    not edi
    and edi, r11d
    or esi, edi
    mov eax, ebx
    jmp .go
.r2:
    mov esi, r11d
    and esi, r9d
    mov edi, r11d
    not edi
    and edi, r10d
    or esi, edi
    lea eax, [rbx+rbx*4+1]
    and eax, 15
    jmp .go
.r3:
    mov esi, r9d
    xor esi, r10d
    xor esi, r11d
    lea eax, [rbx+rbx*2+5]
    and eax, 15
.go:
    add esi, r8d
    add esi, [md5_k+rbx*4]
    add esi, [block+rax*4]
    mov r8d, r11d
    mov r11d, r10d
    mov r10d, r9d
    movzx ecx, byte [md5_s+rbx]
    rol esi, cl
    add r9d, esi
    inc ebx
    cmp ebx, 64
    jb .round
    add r8d, 0x67452301
    add r9d, 0xefcdab89
    add r10d, 0x98badcfe
    add r11d, 0x10325476
    mov [digest], r8d
    mov [digest+4], r9d
    mov [digest+8], r10d
    mov [digest+12], r11d
    pop rbx
    ret

; digest -> 32 lowercase hex chars in hexbuf
to_hex:
    lea rdi, [hexbuf]
    lea rsi, [digest]
    lea rdx, [hexchars]
    xor ecx, ecx
.l:
    movzx eax, byte [rsi+rcx]
    mov r8d, eax
    shr eax, 4
    and r8d, 15
    mov al, [rdx+rax]
    mov [rdi], al
    mov al, [rdx+r8]
    mov [rdi+1], al
    add rdi, 2
    inc ecx
    cmp ecx, 16
    jb .l
    ret

; temp main: print md5 of argv[1]
_start:
    mov rdi, [rsp+16]
    xor esi, esi
    mov rax, rdi
.sl:
    cmp byte [rax+rsi], 0
    je .sd
    inc rsi
    jmp .sl
.sd:
    call md5
    call to_hex
    mov eax, 1
    mov edi, 1
    lea rsi, [hexbuf]
    mov edx, 32
    syscall
    mov eax, 1
    mov edi, 1
    lea rsi, [nl]
    mov edx, 1
    syscall
    mov eax, 60
    xor edi, edi
    syscall

; bf2am - bf2 auto admin over rcon, x86-64 linux, no libc
bits 64
default abs

%include "md5tab.inc"

section .bss
block:    resb 64
digest:   resb 16
hexbuf:   resb 40
sock:     resd 1
rxlen:    resq 1
rxbuf:    resb 16384
cmdbuf:   resb 512
msgbuf:   resb 64
pass_ptr: resq 1
sa:       resb 16

section .data
hexchars: db "0123456789abcdef"
nl:       db 10
s_seed:   db "seed: ", 0
s_ok:     db "uthentication successful", 0
s_login:  db "login ", 0
s_usage:  db "usage: bf2am <ip> <port> <rcon password>", 10, 0
s_authok: db "authenticated", 10, 0
s_authno: db "auth failed", 10, 0
s_noconn: db "cant connect", 10, 0

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


strlen:
    xor eax, eax
.l:
    cmp byte [rdi+rax], 0
    je .d
    inc rax
    jmp .l
.d:
    ret

; rdi = zstr -> stdout
log_z:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov edi, 1
    mov eax, 1
    syscall
    ret

; rdi = dest, rsi = zstr; returns rdi at end
append:
.l:
    mov al, [rsi]
    test al, al
    jz .d
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .l
.d:
    ret

; rdi = hay, rsi = needle -> rax ptr or 0
find_sub:
.outer:
    mov rax, rdi
    mov rdx, rsi
.cmp:
    mov cl, [rdx]
    test cl, cl
    jz .found
    cmp cl, [rax]
    jne .next
    inc rax
    inc rdx
    jmp .cmp
.next:
    cmp byte [rdi], 0
    je .nf
    inc rdi
    jmp .outer
.found:
    mov rax, rdi
    ret
.nf:
    xor eax, eax
    ret

; rdi = "a.b.c.d" -> eax network order
parse_ip:
    xor edx, edx
    xor ecx, ecx
.oct:
    xor eax, eax
.dig:
    movzx esi, byte [rdi]
    sub esi, '0'
    cmp esi, 9
    ja .end
    imul eax, eax, 10
    add eax, esi
    inc rdi
    jmp .dig
.end:
    and eax, 255
    shl eax, cl
    or edx, eax
    add ecx, 8
    cmp ecx, 32
    jae .done
    inc rdi
    jmp .oct
.done:
    mov eax, edx
    ret

parse_uint:
    xor eax, eax
.dig:
    movzx esi, byte [rdi]
    sub esi, '0'
    cmp esi, 9
    ja .d
    imul eax, eax, 10
    add eax, esi
    inc rdi
    jmp .dig
.d:
    ret

; edi = timeout ms. eax = bytes read, 0 on timeout, -1 on eof/error
recv_some:
    sub rsp, 16
    mov eax, [sock]
    mov [rsp], eax
    mov word [rsp+4], 1
    mov word [rsp+6], 0
    mov edx, edi
    mov rdi, rsp
    mov esi, 1
    mov eax, 7
    syscall
    add rsp, 16
    test eax, eax
    jle .none
    mov rdx, 16383
    sub rdx, [rxlen]
    jle .none
    lea rsi, [rxbuf]
    add rsi, [rxlen]
    mov edi, [sock]
    xor eax, eax
    syscall
    test rax, rax
    jle .eof
    add [rxlen], rax
    mov rcx, [rxlen]
    mov byte [rxbuf+rcx], 0
    ret
.none:
    xor eax, eax
    ret
.eof:
    mov eax, -1
    ret

; rdi = end of cmd in cmdbuf
send_cmd:
    lea rsi, [cmdbuf]
    mov rdx, rdi
    sub rdx, rsi
    mov edi, [sock]
    mov eax, 1
    syscall
    ret

; 0 ok, 1 retry, 2 bad auth
connect_login:
    mov eax, 41
    mov edi, 2
    mov esi, 1
    xor edx, edx
    syscall
    test rax, rax
    js .retry
    mov [sock], eax
    mov edi, eax
    lea rsi, [sa]
    mov edx, 16
    mov eax, 42
    syscall
    test rax, rax
    js .retry
    mov qword [rxlen], 0
    mov byte [rxbuf], 0
    mov ebx, 8
.ws:
    mov edi, 2000
    call recv_some
    test eax, eax
    js .retry
    lea rdi, [rxbuf]
    lea rsi, [s_seed]
    call find_sub
    test rax, rax
    jz .more
    lea rsi, [rax+6]
    lea rdx, [rxbuf]
    add rdx, [rxlen]
    lea rcx, [rsi+16]
    cmp rcx, rdx
    ja .more
    mov rax, [rsi]
    mov [msgbuf], rax
    mov rax, [rsi+8]
    mov [msgbuf+8], rax
    jmp .got
.more:
    dec ebx
    jnz .ws
    jmp .retry
.got:
    mov rdi, [pass_ptr]
    call strlen
    cmp rax, 39
    ja .bad
    mov r12, rax
    lea rdi, [msgbuf+16]
    mov rsi, [pass_ptr]
.cp:
    mov al, [rsi]
    test al, al
    jz .cpd
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .cp
.cpd:
    lea rdi, [msgbuf]
    lea rsi, [r12+16]
    call md5
    call to_hex
    lea rdi, [cmdbuf]
    lea rsi, [s_login]
    call append
    lea rsi, [hexbuf]
    mov ecx, 32
.hx:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .hx
    mov byte [rdi], 10
    inc rdi
    call send_cmd
    mov qword [rxlen], 0
    mov byte [rxbuf], 0
    mov ebx, 4
.wa:
    mov edi, 1000
    call recv_some
    lea rdi, [rxbuf]
    lea rsi, [s_ok]
    call find_sub
    test rax, rax
    jnz .ok
    dec ebx
    jnz .wa
.bad:
    mov eax, 2
    ret
.ok:
    xor eax, eax
    ret
.retry:
    mov eax, 1
    ret

usage:
    lea rdi, [s_usage]
    call log_z
    mov eax, 60
    mov edi, 1
    syscall

_start:
    cmp qword [rsp], 4
    jb usage
    lea r13, [rsp+8]
    mov rdi, [r13+8]
    call parse_ip
    mov [sa+4], eax
    mov word [sa], 2
    mov rdi, [r13+16]
    call parse_uint
    xchg al, ah
    mov [sa+2], ax
    mov rax, [r13+24]
    mov [pass_ptr], rax
    call connect_login
    test eax, eax
    jnz .fail
    lea rdi, [s_authok]
    call log_z
    mov eax, 60
    xor edi, edi
    syscall
.fail:
    lea rdi, [s_authno]
    call log_z
    mov eax, 60
    mov edi, 2
    syscall

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
filebuf:  resb 8192
kick_n:   resq 1
kick_tab: resb 32*64
interval: resq 1
ban_n:    resq 1
ban_tab:  resb 32*32
ann_secs: resq 1
ann_text: resb 208
map_secs: resq 1
last_ann: resq 1
map_start: resq 1
state_path: resb 128
act_path: resb 128
statebuf: resb 8192
actbuf:   resb 1024
actlen:   resq 1
px:       resq 1
pz:       resq 1
pscore:   resq 1
tcount:   resq 3
tmin:     resq 3
tmin_txt: resq 3
bal_diff: resq 1
bal_cool: resq 1
last_bal: resq 1
nfz_n:    resq 1
nfz_x:    resq 8
nfz_z:    resq 8
nfz_r2:   resq 8
strikes:  resb 64
nfzmsg:   resb 96
idbuf:    resb 16
namebuf:  resb 64
ipbuf:    resb 24

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
s_rules:  db "rules.conf", 0
s_id:     db "Id: ", 0
s_name:   db "Name: ", 0
s_remote: db " is remote ip: ", 0
s_kw_kick: db "kick ", 0
s_kw_int: db "interval ", 0
s_kw_ban: db "banip ", 0
s_kw_ann: db "announce ", 0
s_kw_map: db "maptime ", 0
s_banc:   db "exec admin.banPlayer ", 0
s_perm:   db " Perm", 0
s_lban:   db "ban ", 0
s_sayc:   db 'exec game.sayAll "', 0
s_kw_state: db "state ", 0
s_kw_act: db "actions ", 0
s_kw_bal: db "balance ", 0
s_kw_nfz: db "nfz ", 0
s_kill:   db "kill ", 0
s_nfz1:   db "no fly zone, pilot id ", 0
s_nfz2:   db " get out", 0
s_nfz3:   db " was killed for flying in the nfz", 0
s_swap:   db "swap ", 0
s_balmsg: db "autobalance: moving a player to the other team", 0
s_nextc:  db "exec admin.runNextLevel", 10, 0
s_lnext:  db "maptime hit, next map", 10, 0
s_listp:  db "exec admin.listPlayers", 10, 0
s_kickc:  db "exec admin.kickPlayer ", 0
s_lkick:  db "kick ", 0
s_gone:   db "lost connection, retrying", 10, 0

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


; rdi = line ptr, rsi = keyword. rax = ptr after keyword or 0
match_kw:
.l:
    mov al, [rsi]
    test al, al
    jz .y
    cmp al, [rdi]
    jne .n
    inc rdi
    inc rsi
    jmp .l
.y:
    mov rax, rdi
    ret
.n:
    xor eax, eax
    ret

; rdi = dest, rsi = src, edx = max len incl nul. lowercases, trims trailing space
copy_lower:
    xor ecx, ecx
    dec edx
.l:
    cmp ecx, edx
    jae .d
    movzx eax, byte [rsi+rcx]
    test al, al
    jz .d
    lea r8d, [rax-'A']
    cmp r8d, 25
    ja .s
    or al, 0x20
.s:
    mov [rdi+rcx], al
    inc ecx
    jmp .l
.d:
    test ecx, ecx
    jz .e
    cmp byte [rdi+rcx-1], ' '
    jne .e
    dec ecx
    jmp .d
.e:
    mov byte [rdi+rcx], 0
    ret

; like copy_lower but keeps case
copy_raw:
    xor ecx, ecx
    dec edx
.l:
    cmp ecx, edx
    jae .d
    mov al, [rsi+rcx]
    test al, al
    jz .d
    mov [rdi+rcx], al
    inc ecx
    jmp .l
.d:
    test ecx, ecx
    jz .e
    cmp byte [rdi+rcx-1], ' '
    jne .e
    dec ecx
    jmp .d
.e:
    mov byte [rdi+rcx], 0
    ret

skip_sp:
    cmp byte [rdi], ' '
    jne .d
    inc rdi
    jmp skip_sp
.d:
    ret

parse_int:
    xor ecx, ecx
    cmp byte [rdi], '-'
    jne .p
    inc rdi
    inc ecx
.p:
    call parse_uint
    test ecx, ecx
    jz .r
    neg rax
.r:
    ret

; rsi = text -> sayAll
say:
    lea rdi, [cmdbuf]
    push rsi
    lea rsi, [s_sayc]
    call append
    pop rsi
    call append
    mov byte [rdi], '"'
    mov byte [rdi+1], 10
    add rdi, 2
    call send_cmd
    ret

; rsi = prefix, rdx = id text -> queue line for actions file
act_add:
    cmp qword [actlen], 900
    jae .d
    lea rdi, [actbuf]
    add rdi, [actlen]
    push rdx
    call append
    pop rsi
    call append
    mov byte [rdi], 10
    inc rdi
    lea rax, [actbuf]
    sub rdi, rax
    mov [actlen], rdi
.d:
    ret

; rdi = buf, r15 = handler(rdi = line). splits on \n and \r
for_lines:
    push r13
    mov r13, rdi
.next:
    mov rdi, r13
    mov rax, r13
.scan:
    mov dl, [rax]
    test dl, dl
    jz .last
    cmp dl, 10
    je .eol
    cmp dl, 13
    je .eol
    inc rax
    jmp .scan
.eol:
    mov byte [rax], 0
    lea r13, [rax+1]
    call r15
    jmp .next
.last:
    call r15
    pop r13
    ret

rule_line:
.sp:
    cmp byte [rdi], ' '
    jne .a
    inc rdi
    jmp .sp
.a:
    cmp byte [rdi], 0
    je .out
    cmp byte [rdi], '#'
    je .out
    mov rbx, rdi
    lea rsi, [s_kw_kick]
    call match_kw
    test rax, rax
    jz .t2
    mov rcx, [kick_n]
    cmp rcx, 32
    jae .out
    mov rsi, rax
    shl rcx, 6
    lea rdi, [kick_tab+rcx]
    mov edx, 64
    call copy_lower
    inc qword [kick_n]
    ret
.t2:
    mov rdi, rbx
    lea rsi, [s_kw_int]
    call match_kw
    test rax, rax
    jz .t3
    mov rdi, rax
    call parse_uint
    test rax, rax
    jz .out
    mov [interval], rax
    ret
.t3:
    mov rdi, rbx
    lea rsi, [s_kw_ban]
    call match_kw
    test rax, rax
    jz .t4
    mov rcx, [ban_n]
    cmp rcx, 32
    jae .out
    mov rsi, rax
    shl rcx, 5
    lea rdi, [ban_tab+rcx]
    mov edx, 32
    call copy_lower
    inc qword [ban_n]
    ret
.t4:
    mov rdi, rbx
    lea rsi, [s_kw_ann]
    call match_kw
    test rax, rax
    jz .t5
    mov rdi, rax
    call parse_uint
    mov [ann_secs], rax
.sk:
    cmp byte [rdi], ' '
    jne .at
    inc rdi
    jmp .sk
.at:
    mov rsi, rdi
    lea rdi, [ann_text]
    xor ecx, ecx
.ac:
    cmp ecx, 200
    jae .ad
    mov al, [rsi+rcx]
    test al, al
    jz .ad
    cmp al, '"'
    jne .as
    mov al, 39
.as:
    mov [rdi+rcx], al
    inc ecx
    jmp .ac
.ad:
    mov byte [rdi+rcx], 0
    ret
.t5:
    mov rdi, rbx
    lea rsi, [s_kw_map]
    call match_kw
    test rax, rax
    jz .t6
    mov rdi, rax
    call parse_uint
    mov [map_secs], rax
    ret
.t6:
    mov rdi, rbx
    lea rsi, [s_kw_state]
    call match_kw
    test rax, rax
    jz .t7
    mov rsi, rax
    lea rdi, [state_path]
    mov edx, 128
    call copy_raw
    ret
.t7:
    mov rdi, rbx
    lea rsi, [s_kw_act]
    call match_kw
    test rax, rax
    jz .t8
    mov rsi, rax
    lea rdi, [act_path]
    mov edx, 128
    call copy_raw
    ret
.t8:
    mov rdi, rbx
    lea rsi, [s_kw_bal]
    call match_kw
    test rax, rax
    jz .t9
    mov rdi, rax
    call parse_uint
    mov [bal_diff], rax
    call skip_sp
    call parse_uint
    mov [bal_cool], rax
    ret
.t9:
    mov rdi, rbx
    lea rsi, [s_kw_nfz]
    call match_kw
    test rax, rax
    jz .out
    mov rcx, [nfz_n]
    cmp rcx, 8
    jae .out
    mov rdi, rax
    call parse_int
    mov rcx, [nfz_n]
    mov [nfz_x+rcx*8], rax
    call skip_sp
    call parse_int
    mov rcx, [nfz_n]
    mov [nfz_z+rcx*8], rax
    call skip_sp
    call parse_uint
    imul rax, rax
    mov rcx, [nfz_n]
    mov [nfz_r2+rcx*8], rax
    inc qword [nfz_n]
.out:
    ret

; rdi = path
load_rules:
    mov eax, 2
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .none
    mov r12, rax
    mov edi, eax
    lea rsi, [filebuf]
    mov edx, 8191
    xor eax, eax
    syscall
    mov rbx, rax
    test rax, rax
    jg .ok
    xor ebx, ebx
.ok:
    mov byte [filebuf+rbx], 0
    mov rdi, r12
    mov eax, 3
    syscall
    lea rdi, [filebuf]
    lea r15, [rule_line]
    call for_lines
.none:
    ret

strcmp:
    mov al, [rdi]
    mov dl, [rsi]
    cmp al, dl
    jne .ne
    test al, al
    jz .eq
    inc rdi
    inc rsi
    jmp strcmp
.eq:
    xor eax, eax
    ret
.ne:
    mov eax, 1
    ret

; announcements + map timer
timers:
    call now
    mov rbx, rax
    cmp qword [ann_secs], 0
    je .nm
    mov rax, rbx
    sub rax, [last_ann]
    cmp rax, [ann_secs]
    jb .nm
    mov [last_ann], rbx
    lea rdi, [cmdbuf]
    lea rsi, [s_sayc]
    call append
    lea rsi, [ann_text]
    call append
    mov byte [rdi], '"'
    mov byte [rdi+1], 10
    add rdi, 2
    call send_cmd
.nm:
    cmp qword [map_secs], 0
    je .td
    mov rax, rbx
    sub rax, [map_start]
    cmp rax, [map_secs]
    jb .td
    mov [map_start], rbx
    lea rdi, [cmdbuf]
    lea rsi, [s_nextc]
    call append
    call send_cmd
    lea rdi, [s_lnext]
    call log_z
.td:
    ret

now:
    sub rsp, 16
    mov edi, 1
    mov rsi, rsp
    mov eax, 228
    syscall
    mov rax, [rsp]
    add rsp, 16
    ret

; rdi = seconds
sleep_secs:
    sub rsp, 16
    mov [rsp], rdi
    mov qword [rsp+8], 0
    mov rdi, rsp
    xor esi, esi
    mov eax, 35
    syscall
    add rsp, 16
    ret

; line handler for listPlayers output
proc_player:
    push rbx
    push r12
    push r14
    mov r12, rdi
    lea rsi, [s_id]
    call find_sub
    test rax, rax
    jz .out
    lea rsi, [rax+4]
.skip:
    cmp byte [rsi], ' '
    jne .id
    inc rsi
    jmp .skip
.id:
    lea rdi, [idbuf]
    xor ecx, ecx
.idl:
    movzx eax, byte [rsi]
    lea edx, [rax-'0']
    cmp edx, 9
    ja .idd
    cmp ecx, 7
    jae .idd
    mov [rdi+rcx], al
    inc ecx
    inc rsi
    jmp .idl
.idd:
    mov byte [rdi+rcx], 0
    test ecx, ecx
    jz .out
    mov rdi, r12
    lea rsi, [s_name]
    call find_sub
    test rax, rax
    jz .out
    lea r14, [rax+6]
    mov rdi, r14
    lea rsi, [s_remote]
    call find_sub
    mov rbx, rax
    test rax, rax
    jnz .hasip
    mov rdi, r14
    call strlen
    mov rcx, rax
    jmp .cn
.hasip:
    mov rcx, rbx
    sub rcx, r14
.cn:
    cmp rcx, 63
    jbe .cl
    mov ecx, 63
.cl:
    lea rdi, [namebuf]
    xor edx, edx
.cl2:
    cmp rdx, rcx
    jae .cd
    movzx eax, byte [r14+rdx]
    lea r8d, [rax-'A']
    cmp r8d, 25
    ja .nl
    or al, 0x20
.nl:
    mov [rdi+rdx], al
    inc rdx
    jmp .cl2
.cd:
    mov byte [rdi+rdx], 0
    mov byte [ipbuf], 0
    test rbx, rbx
    jz .ipd
    lea rsi, [rbx+15]
    lea rdi, [ipbuf]
    xor ecx, ecx
.ipl:
    movzx eax, byte [rsi+rcx]
    cmp al, '.'
    je .ipk
    lea edx, [rax-'0']
    cmp edx, 9
    ja .ipe
.ipk:
    cmp ecx, 20
    jae .ipe
    mov [rdi+rcx], al
    inc ecx
    jmp .ipl
.ipe:
    mov byte [rdi+rcx], 0
.ipd:
    xor ebx, ebx
.kl:
    cmp rbx, [kick_n]
    jae .bans
    lea rdi, [namebuf]
    mov rsi, rbx
    shl rsi, 6
    lea rsi, [kick_tab+rsi]
    call find_sub
    test rax, rax
    jnz .kick
    inc rbx
    jmp .kl
.bans:
    xor ebx, ebx
.bl:
    cmp rbx, [ban_n]
    jae .out
    lea rdi, [ipbuf]
    mov rsi, rbx
    shl rsi, 5
    lea rsi, [ban_tab+rsi]
    call strcmp
    test eax, eax
    jz .ban
    inc rbx
    jmp .bl
.ban:
    lea rdi, [cmdbuf]
    lea rsi, [s_banc]
    call append
    lea rsi, [idbuf]
    call append
    lea rsi, [s_perm]
    call append
    mov byte [rdi], 10
    inc rdi
    call send_cmd
    lea rdi, [cmdbuf]
    lea rsi, [s_lban]
    call append
    lea rsi, [namebuf]
    call append
    mov byte [rdi], 10
    mov byte [rdi+1], 0
    lea rdi, [cmdbuf]
    call log_z
    jmp .out
.kick:
    lea rdi, [cmdbuf]
    lea rsi, [s_kickc]
    call append
    lea rsi, [idbuf]
    call append
    mov byte [rdi], 10
    inc rdi
    call send_cmd
    lea rdi, [cmdbuf]
    lea rsi, [s_lkick]
    call append
    lea rsi, [namebuf]
    call append
    mov byte [rdi], 10
    mov byte [rdi+1], 0
    lea rdi, [cmdbuf]
    call log_z
.out:
    pop r14
    pop r12
    pop rbx
    ret

; P <id> <team> <air> <x> <z> <score> <name>
state_line:
    push rbx
    push r12
    push r14
    cmp word [rdi], 0x2050
    jne .out
    add rdi, 2
    call skip_sp
    mov rsi, rdi
    lea rdx, [idbuf]
    xor ecx, ecx
.ci:
    movzx eax, byte [rsi+rcx]
    lea r8d, [rax-'0']
    cmp r8d, 9
    ja .cd
    cmp ecx, 7
    jae .cd
    mov [rdx+rcx], al
    inc ecx
    jmp .ci
.cd:
    mov byte [rdx+rcx], 0
    call parse_uint
    mov r12, rax
    call skip_sp
    call parse_uint
    mov r14, rax
    call skip_sp
    call parse_uint
    mov rbx, rax
    call skip_sp
    call parse_int
    mov [px], rax
    call skip_sp
    call parse_int
    mov [pz], rax
    call skip_sp
    call parse_int
    mov [pscore], rax
    call nfz_check
    cmp r14, 1
    jb .out
    cmp r14, 2
    ja .out
    inc qword [tcount+r14*8]
    mov rax, [pscore]
    cmp rax, [tmin+r14*8]
    jge .out
    mov [tmin+r14*8], rax
    mov rax, [idbuf]
    mov [tmin_txt+r14*8], rax
.out:
    pop r14
    pop r12
    pop rbx
    ret

; rbx = air flag, r12 = id, idbuf = id text, px/pz = pos
nfz_check:
    and r12d, 63
    cmp rbx, 1
    jne .clear
    xor ecx, ecx
.z:
    cmp rcx, [nfz_n]
    jae .clear
    mov rax, [px]
    sub rax, [nfz_x+rcx*8]
    imul rax, rax
    mov rdx, [pz]
    sub rdx, [nfz_z+rcx*8]
    imul rdx, rdx
    add rax, rdx
    cmp rax, [nfz_r2+rcx*8]
    jbe .in
    inc rcx
    jmp .z
.in:
    inc byte [strikes+r12]
    cmp byte [strikes+r12], 3
    jae .kill
    cmp byte [strikes+r12], 1
    jne .r
    lea rdi, [nfzmsg]
    lea rsi, [s_nfz1]
    call append
    lea rsi, [idbuf]
    call append
    lea rsi, [s_nfz2]
    call append
    mov byte [rdi], 0
    lea rsi, [nfzmsg]
    call say
    ret
.kill:
    mov byte [strikes+r12], 0
    lea rsi, [s_kill]
    lea rdx, [idbuf]
    call act_add
    lea rdi, [nfzmsg]
    lea rsi, [s_nfz1]
    call append
    lea rsi, [idbuf]
    call append
    lea rsi, [s_nfz3]
    call append
    mov byte [rdi], 0
    lea rsi, [nfzmsg]
    call say
.r:
    ret
.clear:
    mov byte [strikes+r12], 0
    ret

; read state file, balance teams, flush actions
run_state:
    cmp byte [state_path], 0
    je .ret
    mov qword [tcount+8], 0
    mov qword [tcount+16], 0
    mov rax, 0x7fffffffffffffff
    mov [tmin+8], rax
    mov [tmin+16], rax
    mov qword [actlen], 0
    mov eax, 2
    lea rdi, [state_path]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .ret
    mov r12, rax
    mov edi, eax
    lea rsi, [statebuf]
    mov edx, 8191
    xor eax, eax
    syscall
    mov rbx, rax
    test rax, rax
    jg .rd
    xor ebx, ebx
.rd:
    mov byte [statebuf+rbx], 0
    mov rdi, r12
    mov eax, 3
    syscall
    lea rdi, [statebuf]
    lea r15, [state_line]
    call for_lines
    ; balance
    cmp qword [bal_diff], 0
    je .flush
    mov rax, [tcount+8]
    mov rcx, [tcount+16]
    mov ebx, 1
    sub rax, rcx
    jge .abs
    neg rax
    mov ebx, 2
.abs:
    cmp rax, [bal_diff]
    jb .flush
    call now
    mov rcx, rax
    sub rcx, [last_bal]
    cmp rcx, [bal_cool]
    jb .flush
    mov [last_bal], rax
    lea rsi, [s_swap]
    mov rdx, [tmin_txt+rbx*8]
    mov [idbuf], rdx
    lea rdx, [idbuf]
    call act_add
    lea rsi, [s_balmsg]
    call say
.flush:
    cmp qword [actlen], 0
    je .ret
    mov eax, 2
    lea rdi, [act_path]
    mov esi, 0x441
    mov edx, 0644o
    syscall
    test rax, rax
    js .ret
    mov r12, rax
    mov edi, eax
    lea rsi, [actbuf]
    mov rdx, [actlen]
    mov eax, 1
    syscall
    mov rdi, r12
    mov eax, 3
    syscall
.ret:
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
    mov qword [interval], 5
    lea rdi, [s_rules]
    cmp qword [rsp], 5
    jb .lr
    mov rdi, [r13+32]
.lr:
    call load_rules
    call now
    mov [last_ann], rax
    mov [map_start], rax
.reconnect:
    call connect_login
    cmp eax, 2
    je .fail
    test eax, eax
    jz .loop
    mov edi, 5
    call sleep_secs
    jmp .reconnect
.loop:
    lea rdi, [s_authok]
    call log_z
.poll:
    call timers
    mov qword [rxlen], 0
    mov byte [rxbuf], 0
    lea rdi, [cmdbuf]
    lea rsi, [s_listp]
    call append
    call send_cmd
.dr:
    mov edi, 700
    call recv_some
    test eax, eax
    jg .dr
    js .lost
    lea rdi, [rxbuf]
    lea r15, [proc_player]
    call for_lines
    call run_state
    mov rdi, [interval]
    call sleep_secs
    jmp .poll
.lost:
    lea rdi, [s_gone]
    call log_z
    mov edi, [sock]
    mov eax, 3
    syscall
    mov edi, 5
    call sleep_secs
    jmp .reconnect
.fail:
    lea rdi, [s_authno]
    call log_z
    mov eax, 60
    mov edi, 2
    syscall

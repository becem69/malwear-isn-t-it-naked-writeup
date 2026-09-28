BITS 64
global start
start:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r15, rsp
    call    xb
xb:
    pop     rbp
    sub     rbp, xb-start
    xor     r9d, r9d
    xor     ecx, ecx
ksum:
    movzx   eax, byte [rbp+rcx]
    add     r9d, eax
    inc     ecx
    cmp     ecx, 64
    jb      ksum
    lea     rsi, [rbp+BC_OFF]
    xor     r11d, r11d
    mov     ecx, BC_LEN
dec_bc:
    mov     al, [rsi+r11]
    xor     al, r9b
    mov     edx, r11d
    imul    edx, edx, 0x9E
    xor     al, dl
    mov     [rsi+r11], al
    inc     r11d
    dec     ecx
    jnz     dec_bc
    lea     r12, [rbp+TAB_OFF]
    lea     rdi, [rbp+BC_OFF]
    lea     r14, [rbp+OUT_OFF]
run_top:
    movzx   eax, byte [rdi]
    inc     rdi
    xor     al, 0xA5
    and     eax, 0x0F
    movsxd  rax, dword [rbp+rax*4+JT_OFF]
    lea     rbx, [rbp+rax]
    jmp     rbx
op_push:
    movzx   eax, byte [rdi]
    inc     rdi
    push    rax
    jmp     run_top
op_pushk:
    movzx   ecx, byte [rdi]
    inc     rdi
    movzx   eax, byte [r12+rcx]
    mov     edx, r9d
    add     edx, ecx
    xor     al, dl
    mov     edx, ecx
    imul    edx, edx, 5
    add     edx, r9d
    and     edx, 7
    mov     cl, dl
    ror     al, cl
    push    rax
    jmp     run_top
op_add:
    pop     rcx
    pop     rax
    add     eax, ecx
    push    rax
    jmp     run_top
op_xor:
    pop     rcx
    pop     rax
    xor     eax, ecx
    push    rax
    jmp     run_top
op_rol:
    movzx   ecx, byte [rdi]
    inc     rdi
    pop     rax
    rol     al, cl
    push    rax
    jmp     run_top
op_mul:
    movzx   ecx, byte [rdi]
    inc     rdi
    pop     rax
    imul    eax, ecx
    push    rax
    jmp     run_top
op_and:
    movzx   ecx, byte [rdi]
    inc     rdi
    pop     rax
    movzx   eax, al
    and     eax, ecx
    push    rax
    jmp     run_top
op_emit:
    pop     rax
    mov     [r14], al
    inc     r14
    jmp     run_top
op_halt:
    mov     rsp, r15
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; syscall.asm (MASM)

; Define the SyscallState structure
SyscallState STRUCT
    vrax QWORD ?
    vrcx QWORD ?
    vrdx QWORD ?
    vr8  QWORD ?
    vr9  QWORD ?
    vr10 QWORD ?
    vrsp QWORD ?
SyscallState ENDS

.CODE

; Declare the function as external C linkage
execute_raw_syscall PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi

    ; Arguments (Windows x64 calling convention):
    ; rcx = rax (syscall number)
    ; rdx = rcx (arg1)
    ; r8  = rdx (arg2)
    ; r9  = r8  (arg3)
    ; Stack: r9 (arg4), stack_args pointer, stack_arg_count, SyscallState pointer

    mov rax, rcx    ; Syscall number
    mov rcx, rdx    ; Arg1
    mov rdx, r8     ; Arg2
    mov r8, r9      ; Arg3
    mov r9, [rbp+48]; Arg4 (5th arg on stack)
    mov r10, rcx    ; Windows syscall moves RCX to R10

    ; Save initial RSP
    mov rbx, rsp

    ; Handle stack arguments
    mov rsi, [rbp+56] ; stack_args pointer (6th arg)
    mov rcx, [rbp+64] ; stack_arg_count (7th arg)
    test rcx, rcx
    jz no_stack_args

    ; Allocate shadow space + stack args (32 bytes shadow + 8 per arg)
    lea rdi, [rcx*8 + 32]
    sub rsp, rdi
    and rsp, -16    ; Align to 16 bytes

    ; Copy stack arguments
    xor rdi, rdi
copy_loop:
    cmp rdi, rcx
    jae done_copy
    mov rax, [rsi + rdi*8]
    mov [rsp + 32 + rdi*8], rax
    inc rdi
    jmp copy_loop

done_copy:
no_stack_args:
    sub rsp, 32     ; Shadow space if no extra args

    ; Save registers to stack before syscall
    push r10
    push r9
    push r8
    push rdx
    push rcx

    syscall         ; Execute syscall

    ; Save post-syscall register state
    mov rdi, [rbp+72]  ; SyscallState pointer (8th arg)
    mov [rdi + SyscallState.vrax], rax
    pop rcx
    mov [rdi + SyscallState.vrcx], rcx
    pop rdx
    mov [rdi + SyscallState.vrdx], rdx
    pop r8
    mov [rdi + SyscallState.vr8], r8
    pop r9
    mov [rdi + SyscallState.vr9], r9
    pop r10
    mov [rdi + SyscallState.vr10], r10
    mov [rdi + SyscallState.vrsp], rsp

    ; Restore stack
    mov rsp, rbx    ; Reset RSP to pre-syscall state

    pop rdi
    pop rsi
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
execute_raw_syscall ENDP

END
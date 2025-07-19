public _syscall_host
.code

_syscall_host proc
	mov		r10, rcx
	mov		eax, [rsp + 40]
	add		rsp, 16
	syscall
	sub		rsp, 16
	ret
_syscall_host endp
END
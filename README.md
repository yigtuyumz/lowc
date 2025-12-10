```
+--------+------------+--------+------+------+------+------+------+------+
|  arch  | syscall NR | return | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 |
+--------+------------+--------+------+------+------+------+------+------+
|  x86   |    eax     |  eax   | ebx  | ecx  | edx  | esi  | edi  | ebp  |
| x86_64 |    rax     |  rax   | rdi  | rsi  | rdx  | r10  | r8   | r9   |
+--------+------------+--------+------+------+------+------+------+------+
```

![aiio](oiia.gif?raw=true)

## Changelog

### [2024-XX-XX] - Code Quality & Optimization Disabling
- **Linker Script (linker.ld)**: Added 4KB alignment for all sections (.text, .rodata, .data, .bss) to ensure proper memory alignment
- **Makefile**: Implemented comprehensive optimization disabling flags (WTFLAGS) including:
  - Inline function optimizations disabled (`-fno-inline`, `-fno-inline-functions`)
  - Loop optimizations disabled (`-fno-unroll-loops`, `-fno-loop-*`)
  - Stack and frame pointer preservation (`-fno-omit-frame-pointer`, `-fno-stack-protector`)
  - PIC/PIE disabled (`-fno-pic`, `-fno-pie`)
  - Red zone disabled for bare metal (`-mno-red-zone`)
  - Tree optimizations completely disabled (`-fno-tree-*`)
  - Linker optimizations disabled (`--no-relax`, `--no-gc-sections`)
- **Source Code (wb12.c)**:
  - Fixed inline assembly
  - All assembly code uses Intel syntax with operand numbers (`%0`, `%1`, `%2`, `%3`)
  - Fixed `_strlenx`, `_writex`, and `_exitx` functions with proper input/output/clobber constraints
  - Removed unused functions (`_testx`, `strlen`)
  - Changed `_wb12` return type from `ub8` to `void`
- **Additional Files**: Added `nolibs.c` - a minimal implementation of LIBC functions and syscalls for bare metal programming

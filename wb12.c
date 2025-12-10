// renames the assembly section name to `_write`

// static void
// _writex(unsigned long long int fd, const void *buf,
//         unsigned long long int count)
// __asm__("_write");

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

// the `static` keyword is useless in wb12 source, cause the entire program is compiled and linked statically.

typedef unsigned long int ub64;
typedef unsigned int ub32;
typedef unsigned char ub8;

typedef long int b64;
typedef int b32;
typedef char b8;

/* calculates the length of given string expression. */
static ub64 _strlenx(const char *rdi) __asm__("_strlen");
/* return the count of bytes written, 247 an error occurs. */
static ub64 _writex(ub64 rdi, const void *rsi, ub64 rdx) __asm__("_write");
static void _exitx(ub64 rdi) __asm__("_exit");

static ub64
_strlenx(const char *rdi)
{
    ub64 result;
    // volatile keyword disables certain optimizations thus we avoid side-effects.
    // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html#Volatile-1
    __asm__ volatile (
        "xor %0, %0\n"                           /* result = 0 */
        "test %1, %1\n"                          /* check if pointer is NULL */
        "jz 1f\n"                                /* if NULL, jump to end */
        "0:\n"                                   /* loop start */
        "cmp BYTE PTR [%1 + %0], 0\n"            /* compare current byte with 0 */
        "je 1f\n"                                /* if null terminator found, exit loop */
        "inc %0\n"                               /* result++ */
        "jmp 0b\n"                               /* continue loop */
        "1:\n"                                   /* end */
        : "=&r"(result)                          /* output: general register, early clobber */
        : "r"(rdi)                               /* input: general register */
        : "memory"                               /* memory clobber */
    );
    return (result);
}

static ub64
_writex(ub64 rdi, const void *rsi, ub64 rdx)
{
    ub64 bytes_written;
    // When we want to store the value of a register into a C variable, we use constraints.
    // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
    __asm__ volatile (
        "mov rax, 0x01\n"                         /* rax = 1 (syscall number for write) */
        "mov rdi, %1\n"                           /* rdi = fd */
        "mov rsi, %2\n"                           /* rsi = buf */
        "mov rdx, %3\n"                           /* rdx = count */
        "syscall\n"                               /* syscall write(fd, buf, count) */
        "mov %0, rax\n"                           /* bytes_written = rax */
        : "=r"(bytes_written)                     /* output: general register */
        : "r"(rdi), "r"(rsi), "r"(rdx)            /* inputs: general registers */
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"  /* clobbers: syscall modifies registers */
    );
    return (bytes_written);
}

static void
_exitx(ub64 rdi)
{
    // when we take a parameter, the compiler automatically sets related registers.
    // rdi is automatically assigned with the value of first parameter of this function. (thanks to calling conventions in Linux)
    __asm__ volatile (
        "mov rax, 60\n"                           /* rax = 60 (syscall number for exit) */
        "mov rdi, %0\n"                           /* rdi = status */
        "syscall\n"                               /* syscall exit(status) */
        :                                         /* no output */
        : "r"(rdi)                                /* input: general register */
        : "rax", "rdi", "rcx", "r11", "memory"    /* clobbers: syscall modifies registers */
    );
}

void
_wb12(void)
{
    const char *str = "wb12!\n";
    ub64 len = _strlenx((const void *) str);

    ub64 ret = _writex(1, str, len);
    if (ret != len) {
        _exitx(EXIT_FAILURE);
    }
    _exitx(EXIT_SUCCESS);
}

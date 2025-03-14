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
    // volatile keyword disables certain optimizations thus we avoid side-effects.
    // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html#Volatile-1
    __asm__ volatile (
        "xor rax, rax\n"                          /* rax = 0 */
        "mov rdi, QWORD PTR [rbp - 0x08]\n"       /* rdi = s */
        "cmp BYTE PTR [rdi], 0\n"                 /* *rdi ?= 0 */
        "je .strlenx_end\n"                       /* goto .strlenx_end if *rdi == 0 */
        ".strlenx_loop:\n"                        /* start loop */
        "inc rax\n"                               /* retval++ */
        "inc rdi\n"                               /* s++ */
        "cmp BYTE PTR [rdi], 0\n"                 /* *s ?= 0 */
        "jne .strlenx_loop\n"                     /* goto .strlenx_loop if *s != 0 */
        ".strlenx_end:\n"                         /* end loop */
    );
}

static ub64
_writex(ub64 rdi, const void *rsi, ub64 rdx)
{
    ub64 bytes_written;
    // When we want to store the value of a register into a C variable, we use `clobbers`.
    // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
    __asm__ volatile (
        "mov rax, 0x01\n"                         /* rax = 1 */
        // "mov rdi, [rbp - 8]\n"                 /* rdi = fd */
        // "mov rsi, [rbp - 16]\n"                /* rsi = buf */
        // "mov rdx, [rbp - 24]\n"                /* rdx = count */
        "syscall\n"                               /* syscall write(fd, buf, count) */
        "mov %0, rax\n"
        // write to bytes_written from a register.
        : "=r"(bytes_written)   /* =r -> register, (var) -> expression which holds register's value */
        :                       /* parameters of clobber expression */
        :                       /* which register is gonna change? */
    );
    return (bytes_written);
}

static void
_exitx(ub64 rdi)
{
    // when we take a parameter, the compiler automatically sets related registers.
    // rdi is automatically assigned with the value of first parameter of this function. (thanks to calling conventions in Linux)
    __asm__ volatile (
        "mov rax, 60\n"             /* rax = 60 */
        // "mov rdi, [rbp - 8]\n"   /* [rbp - 8] is equals to the rdi. no need to set it again. */
        "syscall\n"                 /* syscall exit */
    );
}

// in assembly, the stack pointer is used to access the 7th and subsequent variables.
// each time, the stack pointer is incremented by the size of the variable to access the next one.
// if there is lesser than 6 parameters in function signature, assembler automatically assigns values to the related registers.
static void
_testx(ub64 rdi, ub64 rsi, ub64 rdx, ub64 r10, ub64 r8, ub64 r9, ...)
{
    ub64 x = 0x3131;
}


static ub64
strlen(const char *s)
{
    ub64 ret = 0;
    while (*(s + ret)) {
        ret++;
    }

    return (ret);
}

ub8
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

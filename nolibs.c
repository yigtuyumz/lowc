// Minimal Linux x86_64 "nolibs" syscall & libc implementation demo
// to compile: gcc -nostdlib -nostdinc -ffreestanding -fno-builtin -fno-common -masm=intel -s -Wl,--build-id=0x31313131 -o nolibs nolibs.c


// Flags explanation:
// -nostdlib     : Don't use standard library (no libc)
// -nostdinc     : Don't use standard include directories (no system headers)
// -ffreestanding: Compile for freestanding environment (no standard library available)
// -fno-builtin  : Don't recognize builtin functions (prevents libc function calls)
// -fno-common   : Don't allow common symbols (prevents duplicate definitions)
// -masm=intel   : Use Intel assembly syntax
// -s            : Strip all symbols (equivalent to strip command)
// -Wl,--build-id=sha1:... : Set custom build ID (SHA1 hash)
//                          You can also use other hash functions:
//                          -Wl,--build-id=md5:... (MD5 hash)
//                          -Wl,--build-id=uuid:... (UUID format)
//                          -Wl,--build-id=0x12345678 (hex value)
//                          -o nolibs     : Output filename

// System call numbers (from Linux x86-64 ABI)
// https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_NANOSLEEP 35
#define SYS_SOCKET 41
#define SYS_ACCEPT 43
#define SYS_RECV 45
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_EXIT 60

// https://github.com/openbsd/src/blob/master/sys/sys/fcntl.h
// open-only flags
#define O_RDONLY    0x0000      // open for reading only
#define O_WRONLY    0x0001      // open for writing only
#define O_RDWR      0x0002      // open for reading and writing
#define O_ACCMODE   0x0003      // mask for above modes
#define O_CREAT     0x0200      // create if nonexistent

// https://github.com/openbsd/src/blob/master/include/unistd.h
// standard file descriptors
#define STDIN_FILENO    0   // standard input file descriptor
#define STDOUT_FILENO   1   // standard output file descriptor
#define STDERR_FILENO   2   // standard error file descriptor

// https://github.com/openbsd/src/blob/master/sys/sys/_null.h
#define NULL    ((void *)0)

// https://github.com/openbsd/src/blob/master/sys/sys/limits.h
#define INT_MIN     (-0x7fffffff-1) // min value for an int
#define INT_MAX     0x7fffffff      // max value for an int

// Type definitions (no libc, so we define our own)

typedef struct timespec {
    long tv_sec;
    long tv_nsec;
} timespec;

typedef unsigned int mode_t;
typedef unsigned int socklen_t;

// Socket address structures
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};



// ================== SYSTEM CALL WRAPPERS ==================

static long
syscall1(long sys_num, long a1)
{
    long ret;
    __asm__ __volatile__(
        "mov rax, %[num]\n"
        "mov rdi, %[a1]\n"
        "syscall\n"
        : "=a"(ret)
        : [num] "r"(sys_num), [a1] "r"(a1)
        : "rdi", "rsi", "rdx", "rcx", "r11", "memory"
        // Clobber list: syscall modifies rdi, rsi, rdx, rcx, r11
        // Even though we only use rdi, syscall instruction modifies rcx and r11
    );
    return ret;
}

static long
syscall2(long n, long a1, long a2)
{
    long ret;
    __asm__ __volatile__(
        "mov rax, %[num]\n"
        "mov rdi, %[a1]\n"
        "mov rsi, %[a2]\n"
        "syscall\n"
        : "=a"(ret)
        : [num] "r"(n), [a1] "r"(a1), [a2] "r"(a2)
        : "rdi", "rsi", "rdx", "rcx", "r11", "memory"
        // Clobber list: syscall modifies rdi, rsi, rdx, rcx, r11
        // Without this, GCC might reuse these registers incorrectly
    );
    return ret;
}

static long
syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__(
        // Assembly instructions:
        // Load syscall number and parameters into registers
        "mov rax, %[num]\n"    // rax = syscall number (n)
        "mov rdi, %[a1]\n"     // rdi = first parameter (a1)
        "mov rsi, %[a2]\n"     // rsi = second parameter (a2)
        "mov rdx, %[a3]\n"     // rdx = third parameter (a3)
        "syscall\n"            // Execute system call
        
        // Output operands (what we get back):
        : "=a"(ret)            // Return value: ret = rax (syscall return value)
        
        // Input operands (what we pass in):
        : [num] "r"(n),        // %[num] = n (syscall number) in any register
          [a1] "r"(a1),        // %[a1] = a1 (first param) in any register
          [a2] "r"(a2),        // %[a2] = a2 (second param) in any register
          [a3] "r"(a3)         // %[a3] = a3 (third param) in any register
        
        // Clobber list (registers that get modified):
        // CRITICAL: Without this, GCC might reuse these registers incorrectly!
        : "rdi",               // Modified: used for 1st parameter
          "rsi",               // Modified: used for 2nd parameter
          "rdx",               // Modified: used for 3rd parameter
          "rcx",               // Modified: syscall instruction uses this for return address
          "r11",               // Modified: syscall instruction uses this for flags
          "memory"             // Modified: memory may change (prevents GCC from caching)
        
        // Why clobber list is necessary:
        // ------------------------------
        // GCC doesn't know which registers syscall modifies. If we don't tell it:
        // - GCC might keep variables in rdi/rsi/rdx registers
        // - After syscall, those registers contain different values
        // - Result: corrupted data, wrong calculations
        //
        // Example bug without clobber:
        //   int x = 5;           // GCC stores x in rdi
        //   syscall3(...);       // syscall modifies rdi!
        //   int y = x + 10;      // GCC reads rdi, but it's corrupted! WRONG!
        //
        // With clobber list, GCC knows to:
        // - Save/restore these registers if needed
        // - Not reuse them for other variables
        // - Generate correct code
    );
    return ret;
}

static long
syscall4(long n, long a1, long a2, long a3, long a4)
{
    long ret;
    __asm__ __volatile__(
        "mov rax, %[num]\n"
        "mov rdi, %[a1]\n"
        "mov rsi, %[a2]\n"
        "mov rdx, %[a3]\n"
        "mov rcx, %[a4]\n"
        "syscall\n"
        : "=a"(ret)
        : [num] "r"(n), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3), [a4] "r"(a4)
        : "rdi", "rsi", "rdx", "rcx", "r11", "memory"
        // Clobber list: syscall modifies rdi, rsi, rdx, rcx, r11
        // Note: rcx is used for 4th parameter, but syscall also modifies it
        // r11 is always modified by syscall instruction (flags register)
    );
    return ret;
}


// ================== END OF SYSTEM CALL WRAPPERS ==================











// ================== SYSTEM CALL IMPLEMENTATIONS ==================

// Exit syscall: sys_exit(int status)
static __attribute__((noreturn)) void
sys_exit(int code)
{
    // __asm__ __volatile__(
    //     "mov rax, 60\n"
    //     "mov edi, %[c]\n"    // use edi (32-bit) because code is int (32-bit)
    //     "syscall\n"
    //     :
    //     : [c] "r"(code)
    //     : "rax", "rdi"
    // );
    // __builtin_unreachable();
    syscall2(SYS_EXIT, code, 0);
    __builtin_unreachable();    // this is a builtin function, it tells the compiler that this code is unreachable
}

static void
sys_write(int fd, const char *buf, __SIZE_TYPE__ count)
{
    syscall3(SYS_WRITE, fd, (long)buf, count);
}

// nanosleep syscall: sys_nanosleep(const struct timespec *req, struct timespec *rem)
// Returns 0 on success, -1 on error (e.g., EINTR if interrupted by signal)
static int
sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
    return syscall2(SYS_NANOSLEEP, (long) req, (long) rem);
}

// sleep syscall: sys_sleep(unsigned int seconds)
// Returns 0 on success, -1 on error
static int
sys_sleep(unsigned int seconds)
{
    struct timespec req = { seconds, 0 };
    struct timespec rem;
    return sys_nanosleep(&req, &rem);
}

// implement sys_socket
static int
sys_socket(int domain, int type, int protocol)
{
    return syscall3(SYS_SOCKET, domain, type, protocol);
}

// implement sys_close
static int
sys_close(int fd)
{
    return syscall1(SYS_CLOSE, fd);
}

// implement sys_bind
static int
sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return syscall3(SYS_BIND, sockfd, (long) addr, addrlen);
}

// implement sys_listen
static int
sys_listen(int sockfd, int backlog)
{
    return syscall2(SYS_LISTEN, sockfd, backlog);
}

// implement sys_accept
static int
sys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return syscall3(SYS_ACCEPT, sockfd, (long) addr, (long) addrlen);
}

// implement sys_recv
static int
sys_recv(int sockfd, void *buf, __SIZE_TYPE__ len, int flags)
{
    return syscall4(SYS_RECV, sockfd, (long)buf, len, flags);
}

// implement sys_open
static int
sys_open(const char *pathname, int flags, mode_t mode)
{
    return syscall3(SYS_OPEN, (long)pathname, flags, (long) mode);
}

// implement sys_read
static int
sys_read(int fd, void *buf, __SIZE_TYPE__ len)
{
    return syscall3(SYS_READ, fd, (long) buf, len);
}

// ================== END OF SYSTEM CALL IMPLEMENTATIONS ==================





// ================== LIBC IMPLEMENTATIONS ==================


static void
ft_putnbr(int n)
{
    // Handle INT_MIN (-2147483648) special case to avoid overflow
    if (n == INT_MIN) {
        sys_write(1, "-2147483648", 11);
        return;
    }
    if (n < 0) {
        sys_write(1, "-", 1);
        n = -n;
    }
    if (n > 9) {
        ft_putnbr(n / 10);
    }
    sys_write(1, &"0123456789"[n % 10], 1);
}


static int
printf(const char *format, ...)
{
    __builtin_va_list ap;
    __builtin_va_start(ap, format);
    
    while (*format) {
        if (*format == '%') {
            format++;
            // Check if we reached end of string after %
            if (!*format) {
                sys_write(1, "%", 1);
                break;
            }
            if (*format == 'd') {
                // Get integer argument using GCC builtin
                int value = __builtin_va_arg(ap, int);
                ft_putnbr(value);
            } else if (*format == 's') {
                // Get string pointer argument using GCC builtin
                const char *str = __builtin_va_arg(ap, const char *);
                // Handle NULL pointer
                if (!str) {
                    sys_write(1, "(null)", 6);
                } else {
                    __SIZE_TYPE__ len = 0;
                    while (str[len] && len < 4096) ++len;
                    sys_write(1, str, len);
                }
            } else if (*format == '%') {
                // Handle %% -> print single %
                sys_write(1, "%", 1);
            } else {
                // Unknown format specifier, print it literally
                sys_write(1, "%", 1);
                sys_write(1, format, 1);
            }
        } else {
            sys_write(1, format, 1);
        }
        format++;
    }
    
    __builtin_va_end(ap);
    return 0;
}

// implement memset
// Sets the first n bytes of s to the value c (converted to unsigned char)
static void *
memset(void *s, int c, __SIZE_TYPE__ n)
{
    unsigned char *p = (unsigned char *)s;
    __SIZE_TYPE__ i = 0;
    // Only use the low 8 bits of c (C standard requirement)
    unsigned char uc = (unsigned char)c;
    while (i < n) {
        p[i] = uc;
        i++;
    }
    return s;
}


// implement memcpy
static void *
memcpy(void *dest, const void *src, __SIZE_TYPE__ n)
{
    __SIZE_TYPE__ i = 0;
    while (i < n) {
        ((unsigned char *)dest) [i] = ((unsigned char *)src) [i];
        i++;
    }
    return dest;
}

// implement memmove, consider overlapping memory regions
// Copies n bytes from src to dest, handling overlapping regions correctly
// If dest < src: copy forward (from start to end)
// If dest >= src: copy backward (from end to start) to avoid overwriting source
static void *
memmove(void *dest, const void *src, __SIZE_TYPE__ n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    
    if (d < s) {
        // Forward copy: dest is before src, safe to copy from start
        __SIZE_TYPE__ i = 0;
        while (i < n) {
            d[i] = s[i];
            i++;
        }
    } else if (d > s) {
        // Backward copy: dest is after src, copy from end to avoid overwriting
        __SIZE_TYPE__ i = n;
        while (i > 0) {
            i--;
            d[i] = s[i];
        }
    }
    // If d == s, nothing to copy (same memory region)
    return dest;
}

// ================== END OF LIBC IMPLEMENTATIONS ==================








// The main function
int
main(int argc, char **argv)
{
    // Safety check: argc should always be at least 1, but let's be defensive
    if (argc < 1 || !argv || !argv[0]) {
        sys_write(STDERR_FILENO, "Error: invalid arguments\n", 25);
        return 1;
    }

    int len = 0;
    while (argv[0][len]) len++;
    sys_write(STDOUT_FILENO, "program name: ", 14);
    sys_write(STDOUT_FILENO, argv[0], len);
    sys_write(STDOUT_FILENO, "\n", 1);
    sys_nanosleep(&(struct timespec){ 1, 999999999 }, NULL);
    printf("program name: %s\n", argv[0]);

    len = sys_open("test.txt", O_RDWR, 0644);
    if (len < 0) {
        printf("Error: failed to open file '%s', status: %d\n", "test.txt", len);
        return 1;
    }
    printf("file opened successfully, status: %d\n", len);

    unsigned char buffer[1024];
    int read_len = sys_read(len, buffer, 1024);
    if (read_len < 0) {
        printf("Error: failed to read file '%s', status: %d\n", "test.txt", read_len);
        return 1;
    }
    printf("file read successfully, status: %d\n", read_len);
    printf("file content:\n===========================\n");
    sys_write(STDOUT_FILENO, buffer, read_len);
    printf("\n===========================\n");

    len = sys_close(len);
    if (len < 0) {
        printf("Error: failed to close file '%s', status: %d\n", "test.txt", len);
        return 1;
    }
    printf("file closed successfully, status: %d\n", len);
    return 0;
}

// Custom _start for no-libs setup
// This is the real entry point of a program
// __attribute__((naked)) is used to tell the compiler that this function is
// is not decorated with any other function attributes
// which means it will not have any prologue or epilogue
__attribute__((naked)) void
_start(void)
{
    // https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
    __asm__ __volatile__(
        // argc in [rsp], argv in [rsp+8]
        "xor    rbp, rbp\n"          // Clear frame pointer (required by x86-64 ABI) Frame pointer should be 0 at program start
        "mov    rdi, [rsp]\n"        // Load argc from stack into rdi (1st argument) argc is at [rsp] (top of stack when _start is called)
        "lea    rsi, [rsp+8]\n"      // Load address of argv into rsi (2nd argument) argv is at [rsp+8] (8 bytes after argc, pointer to char* array)
        "and    rsp, -16\n"          // Align stack to 16-byte boundary
                                     // 
                                     // Explanation:
                                     // -16 in binary = 0xFFFFFFF0 (last 4 bits are 0)
                                     // This operation clears the last 4 bits of rsp
                                     // Result: rsp becomes a multiple of 16 (16-byte aligned)
                                     //
                                     // Why is this necessary?
                                     // 1. x86-64 ABI requires stack to be 16-byte aligned
                                     //    before function calls (especially call instruction)
                                     // 2. SSE/AVX instructions require aligned memory access
                                     // 3. Some syscalls and library functions expect aligned stack
                                     //
                                     // Example:
                                     //   If rsp = 0x7FFFFFFF1234 (not aligned)
                                     //   After: rsp = 0x7FFFFFFF1230 (aligned to 16 bytes)
                                     //
                                     // Without this, the program may crash or behave incorrectly
        "call   main\n"              // Call main(argc, argv) main's return value is in rax (exit code)
        "mov    rdi, rax\n"          // Move exit code from rax to rdi (1st syscall argument)
        "call   sys_exit\n"          // Call sys_exit(exit_code) - never returns, it will exit the program with the exit code
        :                           // output operands
        :                           // input operands
        : "rdi", "rsi", "rax"       // clobber list (registers that get modified)
    );
    // https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
    __builtin_unreachable();    // this is a builtin function, it tells the compiler that this code is unreachable
}

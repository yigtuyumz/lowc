// renames the assembly section name to `_write`

// static void
// _writex(unsigned long long int fd, const void *buf,
//         unsigned long long int count)
// __asm__("_write");

static unsigned long long int
_strlenx(const char *s)
{
    __asm__ volatile ("xor rax, rax\n"
                      "mov rdi, [rbp - 8]\n"
                      "cmp byte ptr [rdi], 0\n"
                      "je .end\n"
                      ".loop:\n"
                      "inc rax\n"
                      "inc rdi\n"
                      "cmp byte ptr [rdi], 0\n" "jne .loop\n" ".end:\n");
}

static unsigned long long int
_writex(unsigned long long int fd, const void *buf,
        unsigned long long int count)
{
    __asm__ volatile ("mov rax, 0x01\n"
                      "mov rdi, [rbp - 8]\n"
                      "mov rsi, [rbp - 16]\n"
                      "mov rdx, [rbp - 24]\n" "syscall\n");

}

static void
_exitx(unsigned long long int status)
{
    __asm__ volatile ("mov rax, 60\n" "syscall\n");
}

void
_wb12(void)
{
    const char *str = "wb12!\n";
    unsigned long long int len = _strlenx(str);

    _writex(1, str, len);
    _exitx(0);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Executable memory structure
 * 
 * This structure holds information about memory allocated for any executable code.
 * Memory is allocated via malloc, then aligned to page boundaries and made executable
 * using mprotect() with PROT_EXEC flag.
 * 
 * Struct layout (offsets in bytes):
 *   page_size:      offset 0  - System page size (typically 4096 bytes)
 *   word_size:      offset 8  - CPU word size (8 bytes on x86-64)
 *   exec_mem:       offset 16 - Aligned pointer to executable memory (page-aligned)
 *   requested_size: offset 24 - Number of bytes requested by user
 *   raw_alloc:      offset 32 - Raw pointer returned by malloc (not page-aligned)
 *   page_count:     offset 40 - Number of pages made executable
 * 
 * Memory allocation formula:
 *   Total allocated = requested_size + word_size + page_size - 1
 *   This ensures we have enough space to align to page boundary
 * 
 * Alignment formula:
 *   exec_mem = (raw_alloc + word_size + page_size - 1) & ~(page_size - 1)
 *   This aligns exec_mem to the next page boundary
 * 
 * Executable size calculation:
 *   executable_size = (requested_size + page_size - 1) & ~(page_size - 1)
 *   This rounds up requested_size to the next page boundary
 *   page_count = executable_size / page_size
 */
typedef struct s_execmem {
    size_t  page_size;      // System page size (alignment value, typically 4096)
    size_t  word_size;      // CPU word size (8 bytes on x86-64)
    void    *exec_mem;      // Page-aligned pointer to executable memory
    size_t  requested_size; // Number of bytes requested by user
    void    *raw_alloc;     // Raw pointer from malloc (not page-aligned)
    size_t  page_count;     // Number of pages made executable via mprotect
} t_execmem;

/*
 * Allocate and prepare executable memory
 * 
 * This function:
 *   1. Allocates a t_execmem structure
 *   2. Gets system page size
 *   3. Allocates raw memory with enough space for alignment
 *   4. Aligns memory to page boundary
 *   5. Makes the aligned memory executable using mprotect()
 * 
 * Parameters:
 *   sz - Number of bytes to allocate (will be rounded up to page size)
 * 
 * Returns:
 *   Pointer to t_execmem structure on success, NULL on failure
 * 
 * Memory layout:
 *   [raw_alloc] -> [padding] -> [exec_mem (page-aligned)] -> [executable memory]
 *                   ^word_size + alignment padding
 * 
 * Note: exec_mem is inside raw_alloc, so freeing raw_alloc invalidates exec_mem
 */
t_execmem *
executable_memory(size_t sz)
{
    t_execmem   *ret;
    void        *alloc;
    size_t      page_sz;
    size_t      executable_size;
    size_t      total_alloc_size;

    // Validate input
    if (sz == 0) {
#if __DEBUG__
        fprintf(stderr, "Error: Requested size cannot be zero\n");
#endif // __DEBUG__
        return (NULL);
    }

    // Allocate structure to hold memory information
    ret = (t_execmem *) malloc(sizeof(t_execmem));
    if (!ret) {
        perror("malloc: t_execmem structure");
        return (NULL);
    }

    // Initialize structure fields
    ret->word_size = sizeof(size_t);    // 8 bytes on x86-64
    ret->requested_size = sz;

    // Get system page size (typically 4096 bytes on Linux)
    // WHY: mprotect() only works on page boundaries - it cannot change permissions
    //      for parts of a page, only entire pages. The page size varies by system
    //      (4KB on most systems, but can be 2MB with huge pages).
    // WHAT HAPPENS IF WE DON'T: If we don't know the page size, we can't align
    //      memory correctly, and mprotect() will fail with EINVAL (Invalid argument).
    page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz == -1) {
        perror("sysconf: _SC_PAGESIZE");
        free(ret);
        return (NULL);
    }
    ret->page_size = page_sz;

    // Calculate total memory needed for alignment
    // Formula: requested_size + word_size + page_size - 1
    // WHY: malloc() returns memory that is NOT page-aligned. We need extra space
    //      to find a page-aligned address within the allocated block. The worst case
    //      is when malloc returns an address just 1 byte before a page boundary,
    //      so we need page_size - 1 extra bytes. We also add word_size as padding
    //      (though not strictly necessary, it's a common practice for alignment).
    // WHAT HAPPENS IF WE DON'T: If we only allocate exactly requested_size bytes,
    //      we might not have enough space to find a page-aligned address within
    //      the allocated block, causing alignment to fail or go out of bounds.
    total_alloc_size = ret->requested_size + ret->word_size + ret->page_size - 1;
    alloc = malloc(total_alloc_size);
    if (!alloc) {
        perror("malloc: raw memory allocation");
        free(ret);
        return (NULL);
    }
    ret->raw_alloc = alloc;

    // Align memory to page boundary
    // Formula: (raw_alloc + word_size + page_size - 1) & ~(page_size - 1)
    // WHY: mprotect() REQUIRES the address to be page-aligned (a multiple of page_size).
    //      This is a hardware limitation - memory protection is managed at the page level
    //      by the MMU (Memory Management Unit), not at the byte level.
    //      The formula works by: adding (page_size - 1) to ensure we're past the boundary,
    //      then using bitwise AND with ~(page_size - 1) to round down to the page boundary.
    // WHAT HAPPENS IF WE DON'T: mprotect() will fail with EINVAL error because the address
    //      is not page-aligned. The executable code cannot be executed because the memory
    //      remains non-executable (DEP/NX bit prevents execution).
    // For further reading: https://en.wikipedia.org/wiki/NX_bit
    //                      https://en.wikipedia.org/wiki/W%5EX
    ret->exec_mem = (void *) (((size_t)ret->raw_alloc + ret->word_size + ret->page_size - 1) 
                              & ~(ret->page_size - 1));

    // Calculate executable size (round up to page boundary)
    // Formula: (requested_size + page_size - 1) & ~(page_size - 1)
    // WHY: mprotect() works on entire pages, not partial pages. If you request
    //      100 bytes, we must make at least 1 full page (4096 bytes) executable.
    //      The formula rounds up to the nearest page boundary.
    // WHAT HAPPENS IF WE DON'T: If we use requested_size directly (e.g., 100 bytes),
    //      mprotect() will still work but will make the entire page containing
    //      those 100 bytes executable. However, using the rounded-up size is more
    //      explicit and ensures we're making exactly the number of pages we calculated.
    //      More importantly, if requested_size is not page-aligned and we pass it
    //      to mprotect, it might not cover all the memory we need, leading to
    //      potential segfaults if executable code extends beyond the original size.
    executable_size = ((ret->requested_size + ret->page_size - 1) & ~(ret->page_size - 1));
    ret->page_count = executable_size / ret->page_size;

    // Make memory executable using mprotect
    // PROT_READ | PROT_WRITE | PROT_EXEC allows reading, writing, and executing
    // WHY: By default, malloc() allocates memory with PROT_READ | PROT_WRITE permissions
    //      (executable bit is NOT set). This is a security feature called DEP/NX (Data
    //      Execution Prevention). To execute code, we MUST set PROT_EXEC flag.
    // WHAT HAPPENS IF WE DON'T: Without PROT_EXEC, attempting to execute code at exec_mem
    //      will cause a segmentation fault (SIGSEGV). The CPU will refuse to execute
    //      instructions from non-executable memory. This is why executable code in .data
    //      section segfaults - we need to explicitly make it executable.
    // NOTE: mprotect works on page boundaries, so both exec_mem (address) and
    //       executable_size (length) must be page-aligned - this is why we did alignment above.
    if (mprotect(ret->exec_mem, executable_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect: make memory executable");
        free(ret->raw_alloc);
        free(ret);
        return (NULL);
    }

#if __DEBUG__
    printf("=== Executable Memory Allocation ===\n");
    printf("Requested size:        %zu bytes\n", ret->requested_size);
    printf("Word size:             %zu bytes\n", ret->word_size);
    printf("Page size:             %zu bytes\n", ret->page_size);
    printf("Total malloc size:     %zu bytes\n", total_alloc_size);
    printf("Raw alloc address:     %p\n", ret->raw_alloc);
    printf("Executable mem address: %p\n", ret->exec_mem);
    printf("Alignment offset:      %zu bytes\n", 
        (size_t)ret->exec_mem - (size_t)ret->raw_alloc);
    printf("Executable size:       %zu bytes\n", executable_size);
    printf("Page count:            %zu pages\n", ret->page_count);
    printf("====================================\n");
#endif // __DEBUG__

    return (ret);
}

/*
 * Main function: Execute shellcode in executable memory
 * 
 * This function demonstrates how to use executable_memory() to run shellcode.
 * It allocates executable memory, copies shellcode into it, and executes it.
 * 
 * Note on memory management:
 *   - If shellcode calls execve() or similar syscalls, it replaces the process
 *     and this code never returns (no memory leak, process is replaced)
 *   - If shellcode returns normally, memory is freed
 *   - Most shellcodes don't return, so free() calls are usually unreachable
 * 
 * Shellcode used: execve("/bin/sh", NULL, NULL)
 *   This spawns a shell, replacing the current process
 */
int
main(void)
{
    t_execmem   *mem;

unsigned char sc[] =
        "\x48\xb8\x48\x65\x6c\x6c\x6f\x0a\x00\x00\x50\x48\x89\xe6\xb8\x01"
        "\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x06\x00\x00\x00\x0f\x05"
        "\xb8\x3c\x00\x00\x00\xbf\x31\x00\x00\x00\x0f\x05"
        "\xe8\xd0\xff\xff\xff\xe8\xea\xff\xff\xff\xc3";
    const size_t sclen = 54;  // -1 to exclude null terminator

#if __DEBUG__
    printf("=== Shellcode Execution ===\n");
    printf("Shellcode length: %zu bytes\n", sclen);
    printf("Allocating executable memory...\n");
#endif // __DEBUG__

    // Allocate executable memory
    mem = executable_memory(sclen);
    if (!mem) {
#if __DEBUG__
        fprintf(stderr, "Error: Failed to allocate executable memory\n");
#endif // __DEBUG__
        return (1);
    }

    // Copy shellcode to executable memory
    memcpy(mem->exec_mem, sc, sclen);

#if __DEBUG__
    printf("Shellcode copied to executable memory at %p\n", mem->exec_mem);
    printf("Executing shellcode...\n");
    printf("(If shellcode calls execve, this process will be replaced)\n");
#endif // __DEBUG__

    // Execute shellcode
    // Cast exec_mem to function pointer and call it
    (*(void(*)())mem->exec_mem)();

    // This code is only reached if shellcode returns normally
    // Most shellcodes (like execve) don't return, so this is usually unreachable
#if __DEBUG__
    printf("Warning: Shellcode returned (unusual for execve-based shellcodes)\n");
    printf("Freeing memory...\n");
#endif // __DEBUG__

    // Free allocated memory
    // Note: If shellcode called execve, this code never executes
    free(mem->raw_alloc);  // Free the raw allocation (exec_mem is inside it)
    free(mem);              // Free the structure itself

    return (0);
}

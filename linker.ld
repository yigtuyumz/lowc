PHDRS                               /* Program Headers */
{
    PERM_RX PT_LOAD FLAGS(0x5);     /* Read-Execute segment */
    PERM_RW PT_LOAD FLAGS(0x6);     /* Read-Write segment */
    PERM_RWX PT_LOAD FLAGS(0x7);    /* Read-Write-Execute segment */
}

SECTIONS
{
    . = 0x400000;   /* Starting value of VMA (Virtual Memory Address) */
    .text :         /* .text section: contains executable code */
    {
        *(.text)
    } : PERM_RX
    . = ALIGN(4096);  /* 4KB alignment */

    . = 0x405000;   /* Starting memory address of .rodata section */
    .rodata :       /* .rodata section: contains read-only data */
    {
        *(.rodata)
    } : PERM_RX
    . = ALIGN(4096);  /* 4KB alignment */

    . = 0x410000;   /* Starting memory address of .data section */
    .data :         /* .data section: contains initialized global and static variables */
    {
        *(.data)
    } : PERM_RW
    . = ALIGN(4096);  /* 4KB alignment */

    . = 0x415000;   /* Starting memory address of .bss section */
    .bss :          /* .bss section: contains uninitialized global and static variables */
    {
        *(.bss)
    } : PERM_RW
    . = ALIGN(4096);  /* 4KB alignment */

    /DISCARD/ :     /* Discarded Sections: sections that are not needed and should be discarded  */
    {
        *(.comment)
        *(.note*)
        *(.eh_frame)
    }
}

ENTRY(_wb12)        /* Entry point of the program */

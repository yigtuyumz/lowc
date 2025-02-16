
/* Program Headers */
PHDRS
{
    /* Read-Execute segment */
    PERM_RX PT_LOAD FLAGS(0x5);

    /* Read-Write segment */
    PERM_RW PT_LOAD FLAGS(0x6);

    /* Read-Write-Execute segment */
    PERM_RWX PT_LOAD FLAGS(0x7);
}

SECTIONS
{
    /* Starting value of VMA (Virtual Memory Address) */
    . = 0x400000;

    /* .text section: contains executable code */
    .text :
    {
        *(.text)
    } : PERM_RX

    /* .rodata section: contains read-only data */
    .rodata :
    {
        *(.rodata)
    } : PERM_RX

    /* .data section: contains initialized global and static variables */
    .data :
    {
        *(.data)
    } : PERM_RW

    /* .bss section: contains uninitialized global and static variables */
    .bss :
    {
        *(.bss)
    } : PERM_RW

    /* Discarded Sections: sections that are not needed and should be discarded  */
    /DISCARD/ : {*(.comment) *(.note*) *(.eh_frame) }
}

/* Entry point of the program */
ENTRY(_wb12)

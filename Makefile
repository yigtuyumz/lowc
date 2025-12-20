CC := gcc
LD := ld
AS := nasm

TARGET := wb12

ASFLAGS := -f elf64
CFLAGS := -fno-builtin -nostdlib -s -nodefaultlibs -ffreestanding -nostdinc -fno-toplevel-reorder -masm=intel -O0 -D__BEGIN_TYPEDEFS -D__END_TYPEDEFS
LDFLAGS := -T linker.ld -static --no-relax --entry=_$(TARGET) --no-gc-sections -z noexecstack --build-id=none

# The following command generates WTFLAGS:
# gcc -Q -O0 --help=optimizers 2>&1 | perl -ane 'if ($F[1] =~/enabled/) {$F[0] =~ s/^\s*-f/-fno-/g;push @o,$F[0];}} END {print join(" ", @o)'
WTFLAGS := -fno-aggressive-loop-optimizations		\
				-fno-allocation-dce					\
				-fno-asynchronous-unwind-tables		\
				-fno-auto-inc-dec					\
				-fno-bit-tests						\
				-fno-dce							\
				-fno-early-inlining					\
				-fno-fp-int-builtin-inexact			\
				-fno-function-cse					\
				-fno-gcse-lm						\
				-fno-inline-atomics					\
				-fno-ipa-stack-alignment			\
				-fno-ipa-strict-aliasing			\
				-fno-ira-hoist-pressure				\
				-fno-ira-share-save-slots			\
				-fno-ira-share-spill-slots			\
				-fno-ivopts							\
				-fno-jump-tables					\
				-fno-lifetime-dse					\
				-fno-math-errno						\
				-fno-peephole						\
				-fno-plt							\
				-fno-printf-return-value			\
				-fno-reg-struct-return				\
				-fno-sched-critical-path-heuristic	\
				-fno-sched-dep-count-heuristic		\
				-fno-sched-group-heuristic			\
				-fno-sched-interblock				\
				-fno-sched-last-insn-heuristic		\
				-fno-sched-rank-heuristic			\
				-fno-sched-spec						\
				-fno-sched-spec-insn-heuristic		\
				-fno-sched-stalled-insns-dep		\
				-fno-schedule-fusion				\
				-fno-semantic-interposition			\
				-fno-short-enums					\
				-fno-shrink-wrap-separate			\
				-fno-signed-zeros					\
				-fno-split-ivs-in-unroller			\
				-fno-ssa-backprop					\
				-fno-stack-clash-protection			\
				-fno-stdarg-opt						\
				-fno-trapping-math					\
				-fno-tree-forwprop					\
				-fno-tree-loop-im					\
				-fno-tree-loop-ivcanon				\
				-fno-tree-loop-optimize				\
				-fno-tree-phiprop					\
				-fno-tree-reassoc					\
				-fno-tree-scev-cprop				\
				-fno-unreachable-traps				\
				-mno-red-zone						\
				-fno-inline							\
				-fno-inline-functions				\
				-fno-inline-small-functions			\
				-fno-unroll-loops					\
				-fno-unroll-all-loops				\
				-fno-prefetch-loop-arrays			\
				-fno-loop-interchange				\
				-fno-loop-strip-mine				\
				-fno-loop-block						\
				-fno-omit-frame-pointer				\
				-fno-stack-protector				\
				-fno-pic							\
				-fno-pie							\
				-fno-PIC							\
				-mno-sse							\
				-mno-sse2							\
				-mno-mmx							\
				-fno-common							\
				-fno-strict-aliasing				\
				-fno-align-functions				\
				-fno-align-jumps					\
				-fno-align-loops					\
				-fno-align-labels					\
				-fno-optimize-sibling-calls			\
				-fno-delete-null-pointer-checks		\
				-fno-merge-constants				\
				-fno-merge-all-constants			\
				-fno-caller-saves					\
				-fno-crossjumping					\
				-fno-cse-follow-jumps				\
				-fno-cse-skip-blocks				\
				-fno-gcse							\
				-fno-gcse-las						\
				-fno-rerun-cse-after-loop			\
				-fno-tree-ch						\
				-fno-tree-copy-prop					\
				-fno-tree-copyrename				\
				-fno-tree-dce						\
				-fno-tree-dominator-opts			\
				-fno-tree-dse						\
				-fno-tree-fre						\
				-fno-tree-loop-distribute-patterns	\
				-fno-tree-loop-distribution			\
				-fno-tree-loop-if-convert			\
				-fno-tree-loop-vectorize			\
				-fno-tree-partial-pre				\
				-fno-tree-pre						\
				-fno-tree-sink						\
				-fno-tree-slp-vectorize				\
				-fno-tree-sra						\
				-fno-tree-switch-conversion			\
				-fno-tree-tail-merge				\
				-fno-tree-ter						\
				-fno-tree-vectorize					\
				-fno-tree-vrp

SRC := $(TARGET).c
OBJ := $(TARGET).o
OBJ_WTF := $(TARGET)wtf.o
EXEC := $(TARGET)
EXEC_WTF := $(TARGET)wtf
LINKER_SCRIPT := linker.ld

all: $(EXEC)

$(EXEC): $(OBJ) $(LINKER_SCRIPT)
	$(LD) $(LDFLAGS) $(OBJ) -o $(EXEC)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $(WTFLAGS) -c $(SRC) -o $(OBJ)

wtf: $(EXEC_WTF)

$(EXEC_WTF): $(OBJ_WTF) $(LINKER_SCRIPT)
	$(LD) $(LDFLAGS) $(OBJ_WTF) -o $(EXEC_WTF)

$(OBJ_WTF): $(SRC)
	$(CC) $(CFLAGS) $(WTFLAGS) -c $(SRC) -o $(OBJ_WTF)

i: $(EXEC)
	objdump -D -M intel $(EXEC)

rep: clean all
	objdump -D -M intel $(EXEC) > rep

clean:
	@rm -rf $(OBJ) $(EXEC) $(OBJ_WTF) $(EXEC_WTF)
	@rm -rf nolibs
	@rm -rf executable_memory

re: clean all

fclean: clean

.PHONY: all wtf i rep clean re fclean nolibs

nolibs: nolibs.c
	$(CC) -nostdlib -nostdinc -ffreestanding -fno-toplevel-reorder -fno-builtin -fno-common -masm=intel -s -Wl,--build-id=0x31313131 -o nolibs nolibs.c

executable_memory: executable_memory.c
	$(CC) executable_memory.c -o executable_memory

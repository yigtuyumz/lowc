CC := gcc
LD := ld
AS := nasm

ASFLAGS := -f elf64
CFLAGS := -fno-builtin -nostdlib -nodefaultlibs -ffreestanding -nostdinc -fno-toplevel-reorder -masm=intel -O0
LDFLAGS := -T linker.ld -static

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



TARGET := wb12

all:
	$(CC) $(CFLAGS) -c $(TARGET).c -o $(TARGET).o
	$(LD) $(LDFLAGS) $(TARGET).o -o $(TARGET)
	@rm -rf $(TARGET).o
# strip $(TARGET)

wtf:
	$(CC) $(CFLAGS) $(WTFLAGS) -c $(TARGET).c -o $(TARGET)wtf.o
	$(LD) $(LDFLAGS) $(TARGET)wtf.o -o $(TARGET)wtf
	@rm -rf $(TARGET)wtf.o
# strip $(TARGET)

clean:
	@rm -rf $(TARGET).o $(TARGET) $(TARGET)wtf $(TARGET)wtf.o

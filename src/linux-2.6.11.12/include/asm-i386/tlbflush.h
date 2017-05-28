#ifndef _I386_TLBFLUSH_H
#define _I386_TLBFLUSH_H

#include <linux/config.h>
#include <linux/mm.h>
#include <asm/processor.h>

/*
 * ULK:
 * Rewrites cr3 register back into itself
 */
#define __flush_tlb()							\
	do {								\
		unsigned int tmpreg;					\
									\
		__asm__ __volatile__(					\
			"movl %%cr3, %0;              \n"		\
			"movl %0, %%cr3;  # flush TLB \n"		\
			: "=r" (tmpreg)					\
			:: "memory");					\
	} while (0)

/*
 * Global pages have to be flushed a bit differently. Not a real
 * performance problem because this does not happen often.
 */
#define __flush_tlb_global()						\
	do {								\
		unsigned int tmpreg;					\
									\
		__asm__ __volatile__(					\
			"movl %1, %%cr4;  # turn off PGE     \n"	\
			"movl %%cr3, %0;                     \n"	\
			"movl %0, %%cr3;  # flush TLB        \n"	\
			"movl %2, %%cr4;  # turn PGE back on \n"	\
			: "=&r" (tmpreg)				\
			: "r" (mmu_cr4_features & ~X86_CR4_PGE),	\
			  "r" (mmu_cr4_features)			\
			: "memory");					\
	} while (0)

extern unsigned long pgkern_mask;

/*
 * ULK:
 * Disables global pages by clearing the PGE flag of cr4, 
 * rewrites cr3 register back into itself, and sets again the PGE flag
 */
# define __flush_tlb_all()						\
	do {								\
		if (cpu_has_pge)					\
			__flush_tlb_global();				\
		else							\
			__flush_tlb();					\
	} while (0)

#define cpu_has_invlpg	(boot_cpu_data.x86 > 3)

/*
 * ULK:
 * Executes invlpg assembly language instruction with parameter addr
 */
#define __flush_tlb_single(addr) \
	__asm__ __volatile__("invlpg %0": :"m" (*(char *) addr))

#ifdef CONFIG_X86_INVLPG
# define __flush_tlb_one(addr) __flush_tlb_single(addr)
#else
# define __flush_tlb_one(addr)						\
	do {								\
		if (cpu_has_invlpg)					\
			__flush_tlb_single(addr);			\
		else							\
			__flush_tlb();					\
	} while (0)
#endif

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#ifndef CONFIG_SMP
/*
 * ULK:
 * Flushes all TLB entries of the non-global pages owned by the current process
 */
#define flush_tlb() __flush_tlb()
/*
 * ULK:
 * Flushes all TLB entries (including those that refer to global pages, 
 * that is, pages whose Global flag is set)
 */
#define flush_tlb_all() __flush_tlb_all()
#define local_flush_tlb() __flush_tlb()

/*
 * ULK:
 * Flushes all TLB entries of the non-global pages owned by a given process
 */
static inline void flush_tlb_mm(struct mm_struct *mm)
{
	if (mm == current->active_mm)
		__flush_tlb();
}

/*
 * ULK:
 * Flushes the TLB of a single Page Table entry of a given process
 */
static inline void flush_tlb_page(struct vm_area_struct *vma,
	unsigned long addr)
{
	if (vma->vm_mm == current->active_mm)
		__flush_tlb_one(addr);
}

/*
 * ULK
 * Flushes the TLB entries corresponding to a linear address interval of a given process
 */
static inline void flush_tlb_range(struct vm_area_struct *vma,
	unsigned long start, unsigned long end)
{
	if (vma->vm_mm == current->active_mm)
		__flush_tlb();
}

#else

#include <asm/smp.h>

#define local_flush_tlb() \
	__flush_tlb()

extern void flush_tlb_all(void);
extern void flush_tlb_current_task(void);
extern void flush_tlb_mm(struct mm_struct *);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);

/*
 * ULK:
 * Flushes all TLB entries of the non-global pages owned by the current process
 */
#define flush_tlb()	flush_tlb_current_task()

static inline void flush_tlb_range(struct vm_area_struct * vma, unsigned long start, unsigned long end)
{
	flush_tlb_mm(vma->vm_mm);
}

#define TLBSTATE_OK	1
#define TLBSTATE_LAZY	2

struct tlb_state
{
	struct mm_struct *active_mm;
	int state;
	char __cacheline_padding[L1_CACHE_BYTES-8];
};
DECLARE_PER_CPU(struct tlb_state, cpu_tlbstate);


#endif

/*
 * ULK:
 * Flushes all TLB entries in a given range of linear addresses 
 * (including those that refer to global pages)
 */
#define flush_tlb_kernel_range(start, end) flush_tlb_all()

/*
 * ULK:
 * Flushes the TLB entries of a given contiguous subset of page tables of a given process
 */
static inline void flush_tlb_pgtables(struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
	/* i386 does not keep any page table caches in TLB */
}

#endif /* _I386_TLBFLUSH_H */

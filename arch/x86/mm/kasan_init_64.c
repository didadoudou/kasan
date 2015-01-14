#include <linux/bootmem.h>
#include <linux/kasan.h>
#include <linux/kdebug.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/tlbflush.h>
#include <asm/sections.h>

extern pte_t kasan_early_pte[];
extern pte_t kasan_early_pmd[];
extern pte_t kasan_early_pud[];
extern unsigned char kasan_early_page[PAGE_SIZE];

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern struct range pfn_mapped[E820_X_MAX];

struct vm_struct kasan_vm __initdata = {
	.addr = (void *)KASAN_SHADOW_START,
	.size = (16UL << 40),
};


static int __init map_range(struct range *range)
{
	unsigned long start = kasan_mem_to_shadow(
		(unsigned long)pfn_to_kaddr(range->start));
	unsigned long end = kasan_mem_to_shadow(
		(unsigned long)pfn_to_kaddr(range->end));

	/*
	 * end + 1 here is intentional. We check several shadow bytes in advance
	 * to slightly speed up fastpath. In some rare cases we could cross
	 * boundary of mapped shadow, so we just map some more here.
	 */
	return vmemmap_populate(start, end + 1, NUMA_NO_NODE);
}

static void __init clear_zero_shadow_mapping(unsigned long start,
					unsigned long end)
{
	for (; start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}

void __init kasan_map_zero_shadow(pgd_t *pgd)
{
	int i;
	unsigned long p;

	p = KASAN_SHADOW_START;
	for (i = pgd_index(p); p < KASAN_SHADOW_END; i++, p += PGDIR_SIZE)
		pgd[i] = __pgd(__pa_nodebug(kasan_early_pud) | _KERNPG_TABLE);
}

#ifdef CONFIG_KASAN_INLINE
static int kasan_die_handler(struct notifier_block *self,
			unsigned long val,
			void *data)
{
	if (val == DIE_GPF) {
		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
	}
	return NOTIFY_OK;
}

static struct notifier_block kasan_die_notifier = {
	.notifier_call = kasan_die_handler,
};
#endif

void __init kasan_init(void)
{
	int i;
	unsigned long start, end, shadow_start, shadow_end;

#ifdef CONFIG_KASAN_INLINE
	register_die_notifier(&kasan_die_notifier);
#endif
	vm_area_add_early(&kasan_vm);

	memcpy(early_level4_pgt, init_level4_pgt, sizeof(early_level4_pgt));
	load_cr3(early_level4_pgt);

	clear_zero_shadow_mapping(kasan_mem_to_shadow(PAGE_OFFSET),
				kasan_mem_to_shadow(PAGE_OFFSET + MAXMEM));

	pr_err("KASAN: globals are at %p\n", &early_level4_pgt[0]);
	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		pr_err("KASAN: mapping shadow for %p-%p\n",
			(void*)pfn_to_kaddr(pfn_mapped[i].start), (void*)pfn_to_kaddr(pfn_mapped[i].end));
		if (map_range(&pfn_mapped[i]))
			panic("kasan: unable to allocate shadow!");
	}
	start = __START_KERNEL_map;
	//end = (unsigned long)_end;
	end = __START_KERNEL_map + (2ull << 30) - (10ull << 20);
	shadow_start = kasan_mem_to_shadow(start);
	shadow_end = kasan_mem_to_shadow(end);
	pr_err("KASAN: mapping shadow for %p-%p -> %p-%p\n",
		(void*)start, (void*)end, (void*)shadow_start, (void*)shadow_end);
	clear_zero_shadow_mapping(shadow_start, shadow_end);
	if (vmemmap_populate(shadow_start, shadow_end, NUMA_NO_NODE))
		panic("kasan: unable to allocate shadow!");

/*
	start = MODULES_VADDR;
	end = __START_KERNEL_map + (2ull << 30) - (10ull << 20);
	shadow_start = kasan_mem_to_shadow(start);
	shadow_end = kasan_mem_to_shadow(end);
	pr_err("KASAN: mapping shadow for %p-%p -> %p-%p\n",
		(void*)start, (void*)end, (void*)shadow_start, (void*)shadow_end);
	clear_zero_shadow_mapping(shadow_start, shadow_end);
	if (vmemmap_populate(shadow_start, shadow_end, NUMA_NO_NODE))
		panic("kasan: unable to allocate shadow!");
*/

	__memset(kasan_early_page, 0, PAGE_SIZE);
	load_cr3(init_level4_pgt);
	init_task.kasan_depth = 0;
}

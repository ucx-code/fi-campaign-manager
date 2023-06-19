#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/sched.h>
#include <xen/err.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/pfn.h>
#include <xen/vmap.h>
#include <xen/xmalloc.h>
#include <xen/efi.h>
#include <xen/grant_table.h>
#include <xen/hypercall.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/x86_emulate.h>
#include <asm/e820.h>
#include <asm/hypercall.h>
#include <asm/shared.h>
#include <asm/mem_sharing.h>
#include <public/memory.h>
#include <public/sched.h>
#include <xsm/xsm.h>
#include <xen/trace.h>
#include <asm/setup.h>
#include <asm/fixmap.h>
#include <asm/io_apic.h>
#include <asm/pci.h>
#include <asm/guest.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/grant_table.h>
#include <asm/pv/domain.h>
#include <asm/pv/grant_table.h>
#include <asm/pv/mm.h>
#include "pv/mm.h"
#undef virt_to_mfn
#define virt_to_mfn(v) _mfn(__virt_to_mfn(v))
#define L1_DISALLOW_MASK ((base_disallow_mask | _PAGE_GNTTAB) & ~_PAGE_GLOBAL)
#define L2_DISALLOW_MASK base_disallow_mask
#define l3_disallow_mask(d) (!is_pv_32bit_domain(d) ? \
                             base_disallow_mask : 0xFFFFF198U)
#define L4_DISALLOW_MASK (base_disallow_mask)
#define l1_disallow_mask(d)                                     \
    ((d != dom_io) &&                                           \
     (rangeset_is_empty((d)->iomem_caps) &&                     \
      rangeset_is_empty((d)->arch.ioport_caps) &&               \
      !has_arch_pdevs(d) &&                                     \
      is_pv_domain(d)) ?                                        \
     L1_DISALLOW_MASK : (L1_DISALLOW_MASK & ~PAGE_CACHE_ATTRS))
#define root_pgt_pv_xen_slots ROOT_PAGETABLE_PV_XEN_SLOTS
#define define_get_linear_pagetable(level)                                  \
static int                                                                  \
get_##level##_linear_pagetable(                                             \
    level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d)         \
{                                                                           \
    unsigned long x, y;                                                     \
    unsigned long pfn;                                                      \
                                                                            \
    if ( !opt_pv_linear_pt )                                                \
    {                                                                       \
        gdprintk(XENLOG_WARNING,                                            \
                 "Attempt to create linear p.t. (feature disabled)\n");     \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (level##e_get_flags(pde) & _PAGE_RW) )                             \
    {                                                                       \
        gdprintk(XENLOG_WARNING,                                            \
                 "Attempt to create linear p.t. with write perms\n");       \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (pfn = level##e_get_pfn(pde)) != pde_pfn )                         \
    {                                                                       \
        struct page_info *page, *ptpg = mfn_to_page(_mfn(pde_pfn));         \
                                                                            \
        /* Make sure the page table belongs to the correct domain. */       \
        if ( unlikely(page_get_owner(ptpg) != d) )                          \
            return 0;                                                       \
                                                                            \
        /* Make sure the mapped frame belongs to the correct domain. */     \
        page = get_page_from_mfn(_mfn(pfn), d);                             \
        if ( unlikely(!page) )                                              \
            return 0;                                                       \
                                                                            \
        /*                                                                  \
         * Ensure that the mapped frame is an already-validated page table  \
         * and is not itself having linear entries, as well as that the     \
         * containing page table is not iself in use as a linear page table \
         * elsewhere.                                                       \
         * If so, atomically increment the count (checking for overflow).   \
         */                                                                 \
        if ( !inc_linear_entries(ptpg) )                                    \
        {                                                                   \
            put_page(page);                                                 \
            return 0;                                                       \
        }                                                                   \
        if ( !inc_linear_uses(page) )                                       \
        {                                                                   \
            dec_linear_entries(ptpg);                                       \
            put_page(page);                                                 \
            return 0;                                                       \
        }                                                                   \
        y = page->u.inuse.type_info;                                        \
        do {                                                                \
            x = y;                                                          \
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||        \
                 unlikely((x & (PGT_type_mask|PGT_validated)) !=            \
                          (PGT_##level##_page_table|PGT_validated)) )       \
            {                                                               \
                dec_linear_uses(page);                                      \
                dec_linear_entries(ptpg);                                   \
                put_page(page);                                             \
                return 0;                                                   \
            }                                                               \
        }                                                                   \
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );   \
    }                                                                       \
                                                                            \
    return 1;                                                               \
}
#define PTF_partial_set           (1 << 0)
#define PTF_preemptible           (1 << 2)
#define PTF_defer                 (1 << 3)
#define PTF_retain_ref_on_restart (1 << 4)
#define current_locked_page_set(x)
#define current_locked_page_check(x) true
#define current_locked_page_ne_check(x) true
#define FASTPATH_FLAG_WHITELIST                                     \
    (_PAGE_NX_BIT | _PAGE_AVAIL_HIGH | _PAGE_AVAIL | _PAGE_GLOBAL | \
     _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_USER)
#define l1f_to_lNf(f) (((f) & _PAGE_PRESENT) ? ((f) |  _PAGE_PSE) : (f))
#define lNf_to_l1f(f) (((f) & _PAGE_PRESENT) ? ((f) & ~_PAGE_PSE) : (f))
#define flush_area(v,f) (!local_irq_is_enabled() ?              \
                         flush_area_local((const void *)v, f) : \
                         flush_area_all((const void *)v, f))
#define flush_flags(oldf) do {                 \
    unsigned int o_ = (oldf);                  \
    if ( (o_) & _PAGE_GLOBAL )                 \
        flush_flags |= FLUSH_TLB_GLOBAL;       \
    if ( (flags & _PAGE_PRESENT) &&            \
         (((o_) ^ flags) & PAGE_CACHE_ATTRS) ) \
    {                                          \
        flush_flags |= FLUSH_CACHE;            \
        if ( virt >= DIRECTMAP_VIRT_START &&   \
             virt < HYPERVISOR_VIRT_END )      \
            flush_flags |= FLUSH_VA_VALID;     \
    }                                          \
} while (0)
#define FLAGS_MASK (_PAGE_NX|_PAGE_RW|_PAGE_PRESENT)
#ifdef CONFIG_MM
unsigned char fi_enabled = 0;
unsigned long int iters_before = 0;
unsigned long int iters_after = 0;
unsigned long long int tsc_on_injection = 0;
#endif
l1_pgentry_t l1_fixmap[L1_PAGETABLE_ENTRIES];
paddr_t mem_hotplug;
struct domain *dom_xen, *dom_io, *dom_cow;
unsigned long max_page;
unsigned long total_pages;
bool machine_to_phys_mapping_valid;
struct rangeset* mmio_ro_ranges;
static uint32_t base_disallow_mask;
static s8 opt_mmio_relax;

static int parse_mmio_relax(const char* s)
{
    if (!*s)
        opt_mmio_relax = 1;
    else
        opt_mmio_relax = parse_bool(s, NULL);

    if (opt_mmio_relax < 0 && strcmp(s, "all")){
        opt_mmio_relax = 0;
        return -EINVAL;
    }
    return 0;
}

custom_param("mmio-relax", parse_mmio_relax);

static void init_frametable_chunk(void* start, void* end)
{
    unsigned long s = (unsigned long )(start);
    unsigned long e = (unsigned long )(end);
    unsigned long step;
    mfn_t mfn;
    ASSERT(!(s & ((1 << L2_PAGETABLE_SHIFT) - 1)));
    for (;s < e;s += step << PAGE_SHIFT){
        step = 1UL << (cpu_has_page1gb && !(s & ((1UL << L3_PAGETABLE_SHIFT) - 1)) ? L3_PAGETABLE_SHIFT - PAGE_SHIFT : L2_PAGETABLE_SHIFT - PAGE_SHIFT);
        while (step && s + (step << PAGE_SHIFT) > e + (4 << PAGE_SHIFT))
            step >>= PAGETABLE_ORDER;
        mfn = alloc_boot_pages(step, step);
        map_pages_to_xen(s, mfn, step, PAGE_HYPERVISOR);
    }
    memset(start, 0, end - start);
    memset(end, -1, s - e);
}

void init_frametable(void)
{
    unsigned int sidx, eidx, nidx;
    unsigned int max_idx = (max_pdx + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT;
    struct page_info *end_pg, *top_pg;
    BUILD_BUG_ON(XEN_VIRT_END > FRAMETABLE_VIRT_START);
    BUILD_BUG_ON(FRAMETABLE_VIRT_START & ((1UL << L2_PAGETABLE_SHIFT) - 1));
    for (sidx = 0;;sidx = nidx){
        eidx = find_next_zero_bit(pdx_group_valid, max_idx, sidx);
        nidx = find_next_bit(pdx_group_valid, max_idx, eidx);
        if (nidx >= max_idx)
            break;

        init_frametable_chunk(pdx_to_page(sidx * PDX_GROUP_COUNT), pdx_to_page(eidx * PDX_GROUP_COUNT));
    }
    end_pg = pdx_to_page(max_pdx - 1) + 1;
    top_pg = mem_hotplug ? pdx_to_page(max_idx * PDX_GROUP_COUNT - 1) + 1 : end_pg;
    init_frametable_chunk(pdx_to_page(sidx * PDX_GROUP_COUNT), top_pg);
    memset(end_pg, -1, (unsigned long)top_pg - (unsigned long)end_pg);
}

void arch_init_memory(void)
{
    unsigned long i, pfn, rstart_pfn, rend_pfn, iostart_pfn, ioend_pfn;
    base_disallow_mask = ~(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_AVAIL | _PAGE_AVAIL_HIGH | _PAGE_NX);
    dom_xen = domain_create(DOMID_XEN, NULL, false);
    BUG_ON(IS_ERR(dom_xen));
    INIT_LIST_HEAD(&dom_xen->arch.pdev_list);
    dom_io = domain_create(DOMID_IO, NULL, false);
    BUG_ON(IS_ERR(dom_io));
    INIT_LIST_HEAD(&dom_io->arch.pdev_list);
    dom_cow = domain_create(DOMID_COW, NULL, false);
    BUG_ON(IS_ERR(dom_cow));
    BUG_ON(pvh_boot && trampoline_phys != 0x1000);
    for (i = 0;i < 0x100;i++)
        share_xen_page_with_guest(mfn_to_page(_mfn(i)), dom_io, SHARE_rw);
    for (i = 0, pfn = 0;pfn < max_page;i++){
        while ((i < e820.nr_map) && (e820.map[i].type != E820_RAM) && (e820.map[i].type != E820_UNUSABLE))
            i++;
        if (i >= e820.nr_map){
            rstart_pfn = rend_pfn = max_page;
        }else{
            rstart_pfn = min_t(unsigned long, max_page,
                               PFN_UP(e820.map[i].addr));
            rend_pfn = max_t(unsigned long, rstart_pfn,
                               PFN_DOWN(e820.map[i].addr + e820.map[i].size));
        }
        iostart_pfn = max_t(unsigned long, pfn, 1UL << (20 - PAGE_SHIFT));
        ioend_pfn = min(rstart_pfn, 16UL << (20 - PAGE_SHIFT));
        if (iostart_pfn < ioend_pfn)
            destroy_xen_mappings((unsigned long )(mfn_to_virt(iostart_pfn)), (unsigned long )(mfn_to_virt(ioend_pfn)));

        for (;pfn < rstart_pfn;pfn++){
            if (!mfn_valid(_mfn(pfn)))
                continue;

            share_xen_page_with_guest(mfn_to_page(_mfn(pfn)), dom_io, SHARE_rw);
        }
        pfn = rend_pfn;
    }
    subarch_init_memory();
    efi_init_memory();
    mem_sharing_init();
}

int page_is_ram_type(unsigned long  mfn, unsigned long  mem_type)
{
    uint64_t maddr = pfn_to_paddr(mfn);
    int i;
    for (i = 0;i < e820.nr_map;i++){
        switch (e820.map[i].type){
            case E820_RAM:
                if (mem_type & RAM_TYPE_CONVENTIONAL)
                    break;

                continue;
            case E820_RESERVED:
                if (mem_type & RAM_TYPE_RESERVED)
                    break;

                continue;
            case E820_UNUSABLE:
                if (mem_type & RAM_TYPE_UNUSABLE)
                    break;

                continue;
            case E820_ACPI:
            case E820_NVS:
                if (mem_type & RAM_TYPE_ACPI)
                    break;

                continue;
            default:
                continue;
        }
        if ((e820.map[i].addr <= maddr) && ((e820.map[i].addr + e820.map[i].size) >= (maddr + PAGE_SIZE)))
            return 1;
    }
    return 0;
}

unsigned int page_get_ram_type(mfn_t mfn)
{
    uint64_t last = 0, maddr = mfn_to_maddr(mfn);
    unsigned int i, type = 0;
    for (i = 0;i < e820.nr_map;last = e820.map[i].addr + e820.map[i].size, i++){
        if ((maddr + PAGE_SIZE) > last && maddr < e820.map[i].addr)
            type |= RAM_TYPE_UNKNOWN;

        if ((maddr + PAGE_SIZE) <= e820.map[i].addr || maddr >= (e820.map[i].addr + e820.map[i].size))
            continue;

        switch (e820.map[i].type){
            case E820_RAM:
                type |= RAM_TYPE_CONVENTIONAL;
                break;
            case E820_RESERVED:
                type |= RAM_TYPE_RESERVED;
                break;
            case E820_UNUSABLE:
                type |= RAM_TYPE_UNUSABLE;
                break;
            case E820_ACPI:
            case E820_NVS:
                type |= RAM_TYPE_ACPI;
                break;
            default:
                type |= RAM_TYPE_UNKNOWN;
                break;
        }
    }
    return type ?   : RAM_TYPE_UNKNOWN;
}

unsigned long domain_get_maximum_gpfn(struct domain* d)
{
    if (is_hvm_domain(d))
        return p2m_get_hostp2m(d)->max_mapped_pfn;

    return (arch_get_max_pfn(d) ?   : 1) - 1;
}

void share_xen_page_with_guest(struct page_info* page, struct domain* d, enum XENSHARE_flags flags)
{
    if (page_get_owner(page) == d)
        return;

    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), INVALID_M2P_ENTRY);
    spin_lock(&d->page_alloc_lock);
    page->u.inuse.type_info = (flags == SHARE_ro ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;
    page_set_owner(page, d);

    asm("" : : : "memory");
    ASSERT((page->count_info & ~PGC_xen_heap) == 0);
    if (!d->is_dying){
        page->count_info |= PGC_xen_heap | PGC_allocated | 1;
        if (unlikely(d->xenheap_pages++ == 0))
            get_knownalive_domain(d);

        page_list_add_tail(page, &d->xenpage_list);
    }
    spin_unlock(&d->page_alloc_lock);
}
void free_shared_domheap_page(struct page_info* page)
{
    if (test_and_clear_bit(_PGC_allocated, &page->count_info))
        put_page(page);

    if (!test_and_clear_bit(_PGC_xen_heap, &page->count_info))
        ASSERT_UNREACHABLE();

    page->u.inuse.type_info = 0;
    page_set_owner(page, NULL);
    free_domheap_page(page);
}

void make_cr3(struct vcpu* v, mfn_t mfn)
{
    struct domain* d = v->domain;
    v->arch.cr3 = mfn_x(mfn) << PAGE_SHIFT;
    if (is_pv_domain(d) && d->arch.pv.pcid)
        v->arch.cr3 |= get_pcid_bits(v, false);
}
void write_ptbase(struct vcpu* v)
{
    struct cpu_info* cpu_info = get_cpu_info();
    unsigned long new_cr4;
    new_cr4 = (is_pv_vcpu(v) && !is_idle_vcpu(v)) ? pv_make_cr4(v) : mmu_cr4_features;
    if (is_pv_vcpu(v) && v->domain->arch.pv.xpti){
        cpu_info->root_pgt_changed = true;
        cpu_info->pv_cr3 = __pa(this_cpu(root_pgt));
        if (new_cr4 & X86_CR4_PCIDE)
            cpu_info->pv_cr3 |= get_pcid_bits(v, true);

        switch_cr3_cr4(v->arch.cr3, new_cr4);
    }else{
        cpu_info->use_pv_cr3 = false;
        cpu_info->xen_cr3 = 0;
        switch_cr3_cr4(v->arch.cr3, new_cr4);
        cpu_info->pv_cr3 = 0;
    }
}
void update_cr3(struct vcpu* v)
{
    mfn_t cr3_mfn;
    if (paging_mode_enabled(v->domain)){
        paging_update_cr3(v, false);
        return;
    }
    if (!(v->arch.flags & TF_kernel_mode))
        cr3_mfn = pagetable_get_mfn(v->arch.guest_table_user);
    else
        cr3_mfn = pagetable_get_mfn(v->arch.guest_table);

    make_cr3(v, cr3_mfn);
}

inline static void set_tlbflush_timestamp(struct page_info* page)
{
    if ( !(page->count_info & PGC_page_table) ||
         !shadow_mode_enabled(page_get_owner(page)) )
        page_set_tlbflush_timestamp(page);
}
const char zero_page[PAGE_SIZE];

static int alloc_segdesc_page(struct page_info* page)
{
    const struct domain* owner = page_get_owner(page);
    seg_desc_t* descs = __map_domain_page(page);
    unsigned i;
    for (i = 0;i < 512;i++)
        if (unlikely(!check_descriptor(owner, &descs[i])))
            break;
    unmap_domain_page(descs);
    return i == 512 ? 0 : -EINVAL;
}

static int _get_page_type(struct page_info* page, unsigned long  type, bool preemptible);

static bool inc_linear_entries(struct page_info* pg)
{
    typeof (pg->linear_pt_count) nc = read_atomic(&pg->linear_pt_count), oc;
    do{
        BUILD_BUG_ON(sizeof(nc) >= sizeof(int));
        oc = nc++;
        if (nc <= 0)
            return false;

        nc = cmpxchg(&pg->linear_pt_count, oc, nc);
    } while (oc != nc);
    return true;
}
static void dec_linear_entries(struct page_info* pg)
{
    typeof (pg->linear_pt_count) oc;
    oc = arch_fetch_and_add(&pg->linear_pt_count, -1);
    ASSERT(oc > 0);
}

static bool inc_linear_uses(struct page_info* pg)
{
    typeof (pg->linear_pt_count) nc = read_atomic(&pg->linear_pt_count), oc;
    do{
        BUILD_BUG_ON(sizeof(nc) >= sizeof(int));
        oc = nc--;
        if (nc >= 0)
            return false;

        nc = cmpxchg(&pg->linear_pt_count, oc, nc);
    } while (oc != nc);
    return true;
}

static void dec_linear_uses(struct page_info* pg)
{
    typeof (pg->linear_pt_count) oc;
    oc = arch_fetch_and_add(&pg->linear_pt_count, 1);
    ASSERT(oc < 0);
}

static bool opt_pv_linear_pt = true;
boolean_param("pv-linear-pt", opt_pv_linear_pt);

 bool is_iomem_page(mfn_t mfn)
{
    struct page_info* page;
    if (!mfn_valid(mfn))
        return true;

    page = mfn_to_page(mfn);
    ASSERT((page->count_info & PGC_count_mask) != 0);
    return (page_get_owner(page) == dom_io);
}

static int update_xen_mappings(unsigned long  mfn, unsigned int cacheattr)
{
    int err = 0;
    bool alias = mfn >= PFN_DOWN(xen_phys_start) &&
         mfn < PFN_UP(xen_phys_start + xen_virt_end - XEN_VIRT_START);
    unsigned long xen_va = XEN_VIRT_START + ((mfn - PFN_DOWN(xen_phys_start)) << PAGE_SHIFT);
    if (unlikely(alias) && cacheattr)
        err = map_pages_to_xen(xen_va, _mfn(mfn), 1, 0);

    if (!err)
        err = map_pages_to_xen((unsigned long )(mfn_to_virt(mfn)), _mfn(mfn), 1, PAGE_HYPERVISOR | cacheattr_to_pte_flags(cacheattr));

    if (unlikely(alias) && !cacheattr && !err)
        err = map_pages_to_xen(xen_va, _mfn(mfn), 1, PAGE_HYPERVISOR);

    return err;
}
int get_page_from_l1e(l1_pgentry_t l1e, struct domain* l1e_owner, struct domain* pg_owner)
{
    unsigned long mfn = l1e_get_pfn(l1e);
    struct page_info* page = mfn_to_page(_mfn(mfn));
    uint32_t l1f = l1e_get_flags(l1e);
    struct vcpu* curr = current;
    struct domain* real_pg_owner;
    bool write;
    if (unlikely(!(l1f & _PAGE_PRESENT))){
        ASSERT_UNREACHABLE();
        return 0;
    }
    if (unlikely(l1f & l1_disallow_mask(l1e_owner))){
        gdprintk(XENLOG_WARNING, "Bad L1 flags %x\n", l1f & l1_disallow_mask(l1e_owner));
        return -EINVAL;
    }
    if (!mfn_valid(_mfn(mfn)) || (real_pg_owner = page_get_owner_and_reference(page)) == dom_io){
        int flip = 0;
        if (mfn_valid(_mfn(mfn)))
             put_page(page);

        if (pg_owner == dom_io)
            pg_owner = curr->domain;

        if (!iomem_access_permitted(pg_owner, mfn, mfn)){
            if (mfn != (PADDR_MASK >> PAGE_SHIFT)){
                gdprintk(XENLOG_WARNING, "d%d non-privileged attempt to map MMIO space %05lx\n", pg_owner->domain_id, mfn);
                return -EPERM;
            }
            return -EINVAL;
        }
        if (pg_owner != l1e_owner && !iomem_access_permitted(l1e_owner, mfn, mfn)){
            if (mfn != (PADDR_MASK >> PAGE_SHIFT)){
                gdprintk(XENLOG_WARNING, "d%d attempted to map MMIO space %05lx in d%d to d%d\n", curr->domain->domain_id, mfn, pg_owner->domain_id, l1e_owner->domain_id);
                return -EPERM;
            }
            return -EINVAL;
        }
        if (!rangeset_contains_singleton(mmio_ro_ranges, mfn)){
            switch (opt_mmio_relax){
                case 0:
                    break;
                case 1:
                    if (!is_hardware_domain(l1e_owner))
                        break;

                case -1:
                    return 0;
                default:
                    ASSERT_UNREACHABLE();
            }
        }else
            if (l1f & _PAGE_RW){
                flip = _PAGE_RW;
            }

        switch (l1f & PAGE_CACHE_ATTRS){
            case 0:
                flip |= _PAGE_PWT | _PAGE_PCD;
                break;
            case _PAGE_PWT:
                case _PAGE_PWT | _PAGE_PAT:
                flip |= _PAGE_PCD | (l1f & _PAGE_PAT);
                break;
        }
        return flip;
    }
    if (unlikely( (real_pg_owner != pg_owner) &&
                   (real_pg_owner != dom_cow) )){
        if ((real_pg_owner == NULL) || (pg_owner == l1e_owner) || xsm_priv_mapping(XSM_TARGET, pg_owner, real_pg_owner)){
            gdprintk(XENLOG_WARNING, "pg_owner d%d l1e_owner d%d, but real_pg_owner d%d\n", pg_owner->domain_id, l1e_owner->domain_id, real_pg_owner ? real_pg_owner->domain_id : -1);
            goto could_not_pin;
        }
        pg_owner = real_pg_owner;
    }
    if ((l1f & _PAGE_RW) && (real_pg_owner == dom_cow))
        goto could_not_pin;

    write = (l1f & _PAGE_RW) && ((l1e_owner == pg_owner) || !paging_mode_external(pg_owner));
    if (write && !get_page_type(page, PGT_writable_page)){
        gdprintk(XENLOG_WARNING, "Could not get page type PGT_writable_page\n");
        goto could_not_pin;
    }
    if (pte_flags_to_cacheattr(l1f) != ((page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base)){
        unsigned long x, nx, y = page->count_info;
        unsigned long cacheattr = pte_flags_to_cacheattr(l1f);
        int err;
        if (is_xen_heap_page(page)){
            if (write)
                put_page_type(page);

            put_page(page);
            gdprintk(XENLOG_WARNING, "Attempt to change cache attributes of Xen heap page\n");
            return -EACCES;
        }
        do{
            x = y;
            nx = (x & ~PGC_cacheattr_mask) | (cacheattr << PGC_cacheattr_base);
        } while ((y = cmpxchg(&page->count_info, x, nx)) != x);
        err = update_xen_mappings(mfn, cacheattr);
        if (unlikely(err)){
            cacheattr = y & PGC_cacheattr_mask;
            do{
                x = y;
                nx = (x & ~PGC_cacheattr_mask) | cacheattr;
            } while ((y = cmpxchg(&page->count_info, x, nx)) != x);
            if (write)
                put_page_type(page);

            put_page(page);
            gdprintk(XENLOG_WARNING, "Error updating mappings for mfn %05lx (pfn %05lx, from L1 entry %016lx) for d%d\n", mfn, get_gpfn_from_mfn(mfn), l1e_get_intpte(l1e), l1e_owner->domain_id);
            return err;
        }
    }
    return 0;
    could_not_pin:
    gdprintk(XENLOG_WARNING, "Error getting mfn %05lx (pfn %05lx) from L1 entry %016lx for l1e_owner d%d, pg_owner d%d\n", mfn, get_gpfn_from_mfn(mfn), l1e_get_intpte(l1e), l1e_owner->domain_id, pg_owner->domain_id);
    if (real_pg_owner != NULL)
        put_page(page);

    return -EBUSY;
}
static int get_page_and_type_from_mfn(mfn_t mfn, unsigned long  type, struct domain* d, unsigned int flags)
{
    struct page_info* page = mfn_to_page(mfn);
    int rc;
    bool preemptible = flags & PTF_preemptible,
         partial_set = flags & PTF_partial_set,
         retain_ref  = flags & PTF_retain_ref_on_restart;
    if ( likely(!partial_set) &&
         unlikely(!get_page_from_mfn(mfn, d)) )
        return -EINVAL;

    rc = _get_page_type(page, type, preemptible);
    if (likely(!rc) || partial_set);

    else
        if (page == current->arch.old_guest_table || (retain_ref && rc == -ERESTART))
            ASSERT(preemptible);
        else
            put_page(page);

    return rc;
}
define_get_linear_pagetable(l2);

static int get_page_from_l2e(l2_pgentry_t l2e, unsigned long  pfn, struct domain* d, unsigned int flags)
{
    unsigned long mfn = l2e_get_pfn(l2e);
    int rc;
    if (unlikely((l2e_get_flags(l2e) & L2_DISALLOW_MASK))){
        gdprintk(XENLOG_WARNING, "Bad L2 flags %x\n", l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return -EINVAL;
    }
    ASSERT(!(flags & PTF_preemptible));
    rc = get_page_and_type_from_mfn(_mfn(mfn), PGT_l1_page_table, d, flags);
    if (unlikely(rc == -EINVAL) && get_l2_linear_pagetable(l2e, pfn, d))
        rc = 0;

    return rc;
}
define_get_linear_pagetable(l3);

static int get_page_from_l3e(l3_pgentry_t l3e, unsigned long  pfn, struct domain* d, unsigned int flags)
{
    int rc;
    if (unlikely((l3e_get_flags(l3e) & l3_disallow_mask(d)))){
        gdprintk(XENLOG_WARNING, "Bad L3 flags %x\n", l3e_get_flags(l3e) & l3_disallow_mask(d));
        return -EINVAL;
    }
    rc = get_page_and_type_from_mfn(l3e_get_mfn(l3e), PGT_l2_page_table, d, flags | PTF_preemptible);
    if (unlikely(rc == -EINVAL) && !is_pv_32bit_domain(d) && get_l3_linear_pagetable(l3e, pfn, d))
        rc = 0;

    return rc;
}
define_get_linear_pagetable(l4);

static int get_page_from_l4e(l4_pgentry_t l4e, unsigned long  pfn, struct domain* d, unsigned int flags)
{
    int rc;
    if (unlikely((l4e_get_flags(l4e) & L4_DISALLOW_MASK))){
        gdprintk(XENLOG_WARNING, "Bad L4 flags %x\n", l4e_get_flags(l4e) & L4_DISALLOW_MASK);
        return -EINVAL;
    }
    rc = get_page_and_type_from_mfn(l4e_get_mfn(l4e), PGT_l3_page_table, d, flags | PTF_preemptible);
    if (unlikely(rc == -EINVAL) && get_l4_linear_pagetable(l4e, pfn, d))
        rc = 0;

    return rc;
}
static int _put_page_type(struct page_info* page, unsigned int flags, struct page_info* ptpg);

void put_page_from_l1e(l1_pgentry_t l1e, struct domain* l1e_owner)
{
    unsigned long pfn = l1e_get_pfn(l1e);
    struct page_info* page;
    struct domain* pg_owner;
    if (!(l1e_get_flags(l1e) & _PAGE_PRESENT) || is_iomem_page(_mfn(pfn)))
        return;

    page = mfn_to_page(_mfn(pfn));
    pg_owner = page_get_owner(page);
    if (_PAGE_GNTTAB && (l1e_get_flags(l1e) & _PAGE_GNTTAB) && !l1e_owner->is_shutting_down && !l1e_owner->is_dying){
        gdprintk(XENLOG_WARNING, "Attempt to implicitly unmap a granted PTE %016lx\n", l1e_get_intpte(l1e));
        domain_crash(l1e_owner);
    }
    if ((l1e_get_flags(l1e) & _PAGE_RW) && ((l1e_owner == pg_owner) || !paging_mode_external(pg_owner))){
        put_page_and_type(page);
    }else{
        put_page(page);
    }
}
static void put_data_page(struct page_info* page, bool writeable)
{
    if (writeable)
        put_page_and_type(page);
    else
        put_page(page);
}

static int put_page_from_l2e(l2_pgentry_t l2e, unsigned long  pfn, unsigned int flags)
{
    int rc = 0;
    if (!(l2e_get_flags(l2e) & _PAGE_PRESENT) || (l2e_get_pfn(l2e) == pfn))
        return 1;

    if (l2e_get_flags(l2e) & _PAGE_PSE){
        struct page_info* page = l2e_get_page(l2e);
        bool writeable = l2e_get_flags(l2e) & _PAGE_RW;
        unsigned int i;
        ASSERT(!(mfn_x(page_to_mfn(page)) &
                 ((1UL << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)));
        for (i = 0;i < (1u << PAGETABLE_ORDER);i++, page++)
            put_data_page(page, writeable);
    }else{
        struct page_info* pg = l2e_get_page(l2e);
        struct page_info* ptpg = mfn_to_page(_mfn(pfn));
        if (flags & PTF_defer){
            current->arch.old_guest_ptpg = ptpg;
            current->arch.old_guest_table = pg;
            current->arch.old_guest_table_partial = false;
        }else{
            rc = _put_page_type(pg, flags | PTF_preemptible, ptpg);
            if (likely(!rc))
                put_page(pg);
        }
    }
    return rc;
}
static int put_page_from_l3e(l3_pgentry_t l3e, unsigned long  pfn, unsigned int flags)
{
    struct page_info* pg;
    int rc;
    if (!(l3e_get_flags(l3e) & _PAGE_PRESENT) || (l3e_get_pfn(l3e) == pfn))
        return 1;

    if (unlikely(l3e_get_flags(l3e) & _PAGE_PSE)){
        unsigned long mfn = l3e_get_pfn(l3e);
        bool writeable = l3e_get_flags(l3e) & _PAGE_RW;
        ASSERT(!(flags & PTF_partial_set));
        ASSERT(!(mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)));
        do{
            put_data_page(mfn_to_page(_mfn(mfn)), writeable);
        } while (++mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1));
        return 0;
    }
    pg = l3e_get_page(l3e);
    if (flags & PTF_defer){
        ASSERT(!(flags & PTF_partial_set));
        current->arch.old_guest_ptpg = mfn_to_page(_mfn(pfn));
        current->arch.old_guest_table = pg;
        current->arch.old_guest_table_partial = false;
        return 0;
    }
    rc = _put_page_type(pg, flags | PTF_preemptible, mfn_to_page(_mfn(pfn)));
    if (likely(!rc))
        put_page(pg);

    return rc;
}

static int put_page_from_l4e(l4_pgentry_t l4e, unsigned long  pfn, unsigned int flags)
{
    int rc = 1;
    if ((l4e_get_flags(l4e) & _PAGE_PRESENT) && (l4e_get_pfn(l4e) != pfn)){
        struct page_info* pg = l4e_get_page(l4e);
        if (flags & PTF_defer){
            ASSERT(!(flags & PTF_partial_set));
            current->arch.old_guest_ptpg = mfn_to_page(_mfn(pfn));
            current->arch.old_guest_table = pg;
            current->arch.old_guest_table_partial = false;
            return 0;
        }
        rc = _put_page_type(pg, flags | PTF_preemptible, mfn_to_page(_mfn(pfn)));
        if (likely(!rc))
            put_page(pg);
    }
    return rc;
}
static int alloc_l1_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    l1_pgentry_t* pl1e;
    unsigned int i;
    int ret = 0;
    pl1e = __map_domain_page(page);
    for (i = 0;i < L1_PAGETABLE_ENTRIES;i++){
        if (!(l1e_get_flags(pl1e[i]) & _PAGE_PRESENT)){
            ret = pv_l1tf_check_l1e(d, pl1e[i]) ? -EINTR : 0;
            if (ret)
                goto out;
        }else{
            switch (ret = get_page_from_l1e(pl1e[i], d, d)){
                default:
                    goto fail;
                case 0:
                    break;
                    case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
                    ASSERT(!(ret & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
                    l1e_flip_flags(pl1e[i], ret);
                    break;
            }
        }
        pl1e[i] = adjust_guest_l1e(pl1e[i], d);
    }
    unmap_domain_page(pl1e);
    return 0;
    fail:
    gdprintk(XENLOG_WARNING, "Failure in alloc_l1_table: slot %#x\n", i);
    out:
    while (i-- > 0)
        put_page_from_l1e(pl1e[i], d);
    unmap_domain_page(pl1e);
    return ret;
}

static int create_pae_xen_mappings(struct domain* d, l3_pgentry_t* pl3e)
{
    struct page_info* page;
    l3_pgentry_t l3e3;
    if (!is_pv_32bit_domain(d))
        return 1;

    pl3e = (l3_pgentry_t*)(((unsigned long )(pl3e) & PAGE_MASK));
    l3e3 = pl3e[3];
    if (!(l3e_get_flags(l3e3) & _PAGE_PRESENT)){
        gdprintk(XENLOG_WARNING, "PAE L3 3rd slot is empty\n");
        return 0;
    }
    page = l3e_get_page(l3e3);
    BUG_ON(page->u.inuse.type_info & PGT_pinned);
    BUG_ON((page->u.inuse.type_info & PGT_count_mask) == 0);
    BUG_ON(!(page->u.inuse.type_info & PGT_pae_xen_l2));
    if ((page->u.inuse.type_info & PGT_count_mask) != 1){
        gdprintk(XENLOG_WARNING, "PAE L3 3rd slot is shared\n");
        return 0;
    }
    return 1;
}
static int alloc_l2_table(struct page_info* page, unsigned long  type)
{
    struct domain* d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l2_pgentry_t* pl2e;
    unsigned int i;
    int rc = 0;
    unsigned int partial_flags = page->partial_flags;
    pl2e = map_domain_page(_mfn(pfn));
    for (i = page->nr_validated_ptes;i < L2_PAGETABLE_ENTRIES;i++, partial_flags = 0){
        l2_pgentry_t l2e = pl2e[i];
        if (i > page->nr_validated_ptes && hypercall_preempt_check())
            rc = -EINTR;
        else
            if (!is_guest_l2_slot(d, type, i))
                continue;
            else
                if (!(l2e_get_flags(l2e) & _PAGE_PRESENT)){
                    if (!pv_l1tf_check_l2e(d, l2e))
                        continue;

                    rc = -EINTR;
                }else
                    rc = get_page_from_l2e(l2e, pfn, d, partial_flags);

        ASSERT(rc != -ERESTART);
        if (rc == -EINTR && i){
            page->nr_validated_ptes = i;
            page->partial_flags = partial_flags;
            ;
            rc = -ERESTART;
        }else
            if (rc < 0 && rc != -EINTR){
                gdprintk(XENLOG_WARNING, "Failure in alloc_l2_table: slot %#x\n", i);
                ASSERT(current->arch.old_guest_table == NULL);
                if (i){
                    ASSERT(current->arch.old_guest_table == NULL);
                    page->nr_validated_ptes = i;
                    page->partial_flags = partial_flags;
                    current->arch.old_guest_ptpg = NULL;
                    current->arch.old_guest_table = page;
                    current->arch.old_guest_table_partial = true;
                }
            }

        if (rc < 0)
            break;

        pl2e[i] = adjust_guest_l2e(l2e, d);
    }
    if (!rc && (type & PGT_pae_xen_l2))
        init_xen_pae_l2_slots(pl2e, d);

    unmap_domain_page(pl2e);
    return rc;
}

static int alloc_l3_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l3_pgentry_t* pl3e;
    unsigned int i;
    int rc = 0;
    unsigned int partial_flags = page->partial_flags;
    l3_pgentry_t l3e = l3e_empty();
    pl3e = map_domain_page(_mfn(pfn));
    if (is_pv_32bit_domain(d))
        memset(pl3e + 4, 0, (L3_PAGETABLE_ENTRIES - 4) * sizeof(*pl3e));

    for (i = page->nr_validated_ptes;i < L3_PAGETABLE_ENTRIES;i++, partial_flags = 0){
        l3e = pl3e[i];
        if (i > page->nr_validated_ptes && hypercall_preempt_check())
            rc = -EINTR;
        else
            if (is_pv_32bit_domain(d) && (i == 3)){
                if (!(l3e_get_flags(l3e) & _PAGE_PRESENT) || (l3e_get_flags(l3e) & l3_disallow_mask(d)))
                    rc = -EINVAL;
                else
                    rc = get_page_and_type_from_mfn(l3e_get_mfn(l3e), PGT_l2_page_table | PGT_pae_xen_l2, d, partial_flags | PTF_preemptible | PTF_retain_ref_on_restart);
            }else
                if (!(l3e_get_flags(l3e) & _PAGE_PRESENT)){
                    if (!pv_l1tf_check_l3e(d, l3e))
                        continue;

                    rc = -EINTR;
                }else
                    rc = get_page_from_l3e(l3e, pfn, d, partial_flags | PTF_retain_ref_on_restart);

        if (rc == -ERESTART){
            page->nr_validated_ptes = i;
            page->partial_flags = PTF_partial_set;
        }else
            if (rc == -EINTR && i){
                page->nr_validated_ptes = i;
                page->partial_flags = partial_flags;
                rc = -ERESTART;
            }

        if (rc < 0)
            break;

        pl3e[i] = adjust_guest_l3e(l3e, d);
    }
    if (!rc && !create_pae_xen_mappings(d, pl3e))
        rc = -EINVAL;

    if (rc < 0 && rc != -ERESTART && rc != -EINTR){
        gdprintk(XENLOG_WARNING, "Failure in alloc_l3_table: slot %#x\n", i);
        if (i){
            page->nr_validated_ptes = i;
            page->partial_flags = partial_flags;
            if (current->arch.old_guest_table){
                if (current->arch.old_guest_table == l3e_get_page(l3e)){
                    ASSERT(current->arch.old_guest_table_partial);
                    page->partial_flags = PTF_partial_set;
                }else
                    ASSERT_UNREACHABLE();
            }
            current->arch.old_guest_ptpg = NULL;
            current->arch.old_guest_table = page;
            current->arch.old_guest_table_partial = true;
        }
        while (i-- > 0)
            pl3e[i] = unadjust_guest_l3e(pl3e[i], d);
    }
    unmap_domain_page(pl3e);
    return rc;
}
void init_xen_pae_l2_slots(l2_pgentry_t* l2t, const struct domain* d)
{
    memcpy(&l2t[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
           &compat_idle_pg_table_l2[
               l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
           COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*l2t));
}

void init_xen_l4_slots(l4_pgentry_t* l4t, mfn_t l4mfn, const struct domain* d, mfn_t sl4mfn, bool ro_mpt)
{
    bool short_directmap = d && !paging_mode_external(d);
    l4t[l4_table_offset(RO_MPT_VIRT_START)] =
        ro_mpt ? idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)]
               : l4e_empty();
    l4t[l4_table_offset(PCI_MCFG_VIRT_START)] = idle_pg_table[l4_table_offset(PCI_MCFG_VIRT_START)];
    ASSERT(!mfn_eq(l4mfn, INVALID_MFN));
    l4t[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_mfn(l4mfn, __PAGE_HYPERVISOR_RW);
    l4t[l4_table_offset(SH_LINEAR_PT_VIRT_START)] =
        mfn_eq(sl4mfn, INVALID_MFN) ? l4e_empty() :
        l4e_from_mfn(sl4mfn, __PAGE_HYPERVISOR_RW);
    l4t[l4_table_offset(PERDOMAIN_VIRT_START)] =
        d ? l4e_from_page(d->arch.perdomain_l3_pg, __PAGE_HYPERVISOR_RW)
          : l4e_empty();
    {
        unsigned int slots = (short_directmap ? ROOT_PAGETABLE_PV_XEN_SLOTS : ROOT_PAGETABLE_XEN_SLOTS);
        memcpy(&l4t[l4_table_offset(XEN_VIRT_START)],
               &idle_pg_table[l4_table_offset(XEN_VIRT_START)],
               (ROOT_PAGETABLE_FIRST_XEN_SLOT + slots -
                l4_table_offset(XEN_VIRT_START)) * sizeof(*l4t));
    }
}

bool fill_ro_mpt(mfn_t mfn)
{
    l4_pgentry_t* l4tab = map_domain_page(mfn);
    bool ret = false;
    if (!l4e_get_intpte(l4tab[l4_table_offset(RO_MPT_VIRT_START)])){
        l4tab[l4_table_offset(RO_MPT_VIRT_START)] = idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)];
        ret = true;
    }
    unmap_domain_page(l4tab);
    return ret;
}

void zap_ro_mpt(mfn_t mfn)
{
    l4_pgentry_t* l4tab = map_domain_page(mfn);
    l4tab[l4_table_offset(RO_MPT_VIRT_START)] = l4e_empty();
    unmap_domain_page(l4tab);
}

static int alloc_l4_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l4_pgentry_t* pl4e = map_domain_page(_mfn(pfn));
    unsigned int i;
    int rc = 0;
    unsigned int partial_flags = page->partial_flags;
    for (i = page->nr_validated_ptes;i < L4_PAGETABLE_ENTRIES;i++, partial_flags = 0){
        l4_pgentry_t l4e;
        if (!is_guest_l4_slot(d, i))
            continue;

        l4e = pl4e[i];
        if (!(l4e_get_flags(l4e) & _PAGE_PRESENT)){
            if (!pv_l1tf_check_l4e(d, l4e))
                continue;

            rc = -EINTR;
        }else
            rc = get_page_from_l4e(l4e, pfn, d, partial_flags | PTF_retain_ref_on_restart);

        if (rc == -ERESTART){
            page->nr_validated_ptes = i;
            page->partial_flags = PTF_partial_set;
        }else
            if (rc < 0){
                if (rc != -EINTR)
                    gdprintk(XENLOG_WARNING, "Failure in alloc_l4_table: slot %#x\n", i);

                if (i){
                    page->nr_validated_ptes = i;
                    page->partial_flags = partial_flags;
                    if (rc == -EINTR)
                        rc = -ERESTART;
                    else{
                        if (current->arch.old_guest_table){
                            if (current->arch.old_guest_table == l4e_get_page(l4e)){
                                ASSERT(current->arch.old_guest_table_partial);
                                page->partial_flags = PTF_partial_set;
                            }else
                                ASSERT_UNREACHABLE();
                        }
                        current->arch.old_guest_ptpg = NULL;
                        current->arch.old_guest_table = page;
                        current->arch.old_guest_table_partial = true;
                    }
                }
            }

        if (rc < 0){
            unmap_domain_page(pl4e);
            return rc;
        }
        pl4e[i] = adjust_guest_l4e(l4e, d);
    }
    if (!rc){
        init_xen_l4_slots(pl4e, _mfn(pfn), d, INVALID_MFN, VM_ASSIST(d, m2p_strict));
        atomic_inc(&d->arch.pv.nr_l4_pages);
    }
    unmap_domain_page(pl4e);
    return rc;
}

static void free_l1_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    l1_pgentry_t* pl1e;
    unsigned int i;
    pl1e = __map_domain_page(page);
    for (i = 0;i < L1_PAGETABLE_ENTRIES;i++)
        put_page_from_l1e(pl1e[i], d);
    unmap_domain_page(pl1e);
}

static int free_l2_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l2_pgentry_t* pl2e;
    int rc = 0;
    unsigned int partial_flags = page->partial_flags, i = page->nr_validated_ptes - !(partial_flags & PTF_partial_set);
    pl2e = map_domain_page(_mfn(pfn));
    for (;;){
        if (is_guest_l2_slot(d, page->u.inuse.type_info, i))
            rc = put_page_from_l2e(pl2e[i], pfn, partial_flags);

        if (rc < 0)
            break;

        partial_flags = 0;
        if (!i--)
            break;

        if (hypercall_preempt_check()){
            rc = -EINTR;
            break;
        }
    }
    unmap_domain_page(pl2e);
    if (rc >= 0){
        page->u.inuse.type_info &= ~PGT_pae_xen_l2;
        rc = 0;
    }else
        if (rc == -ERESTART){
            page->nr_validated_ptes = i;
            page->partial_flags = PTF_partial_set;
        }else
            if (rc == -EINTR && i < L2_PAGETABLE_ENTRIES - 1){
                page->nr_validated_ptes = i + !(partial_flags & PTF_partial_set);
                page->partial_flags = partial_flags;
                rc = -ERESTART;
            }

    return rc;
}
static int free_l3_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l3_pgentry_t* pl3e;
    int rc = 0;
    unsigned int partial_flags = page->partial_flags, i = page->nr_validated_ptes - !(partial_flags & PTF_partial_set);
    pl3e = map_domain_page(_mfn(pfn));
    for (;;){
        rc = put_page_from_l3e(pl3e[i], pfn, partial_flags);
        if (rc < 0)
            break;

        partial_flags = 0;
        if (rc == 0)
            pl3e[i] = unadjust_guest_l3e(pl3e[i], d);

        if (!i--)
            break;

        if (hypercall_preempt_check()){
            rc = -EINTR;
            break;
        }
    }
    unmap_domain_page(pl3e);
    if (rc == -ERESTART){
        page->nr_validated_ptes = i;
        page->partial_flags = PTF_partial_set;
    }else
        if (rc == -EINTR && i < L3_PAGETABLE_ENTRIES - 1){
            page->nr_validated_ptes = i + !(partial_flags & PTF_partial_set);
            page->partial_flags = partial_flags;
            rc = -ERESTART;
        }

    return rc > 0 ? 0 : rc;
}

static int free_l4_table(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l4_pgentry_t* pl4e = map_domain_page(_mfn(pfn));
    int rc = 0;
    unsigned partial_flags = page->partial_flags, i = page->nr_validated_ptes - !(partial_flags & PTF_partial_set);
    do{
        if (is_guest_l4_slot(d, i))
            rc = put_page_from_l4e(pl4e[i], pfn, partial_flags);

        if (rc < 0)
            break;

        partial_flags = 0;
    } while (i--);
    if (rc == -ERESTART){
        page->nr_validated_ptes = i;
        page->partial_flags = PTF_partial_set;
    }else
        if (rc == -EINTR && i < L4_PAGETABLE_ENTRIES - 1){
            page->nr_validated_ptes = i + !(partial_flags & PTF_partial_set);
            page->partial_flags = partial_flags;
            rc = -ERESTART;
        }

    unmap_domain_page(pl4e);
    if (rc >= 0){
        atomic_dec(&d->arch.pv.nr_l4_pages);
        rc = 0;
    }
    return rc;
}

int page_lock(struct page_info* page)
{
    unsigned long x, nx;
    ASSERT(current_locked_page_check(NULL));
    do{
        while ((x = page->u.inuse.type_info) & PGT_locked)
            cpu_relax();
        nx = x + (1 | PGT_locked);
        if (!(x & PGT_validated) || !(x & PGT_count_mask) || !(nx & PGT_count_mask))
            return 0;
    } while (cmpxchg(&page->u.inuse.type_info, x, nx) != x);
    ;
    return 1;
}

void page_unlock(struct page_info* page)
{
    unsigned long x, nx, y = page->u.inuse.type_info;
    ASSERT(current_locked_page_check(page));
    do{
        x = y;
        ASSERT((x & PGT_count_mask) && (x & PGT_locked));
        nx = x - (1 | PGT_locked);
        ASSERT(nx & PGT_count_mask);
    } while ((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x);
    ;
}

static int mod_l1_entry(l1_pgentry_t* pl1e, l1_pgentry_t nl1e, unsigned long  gl1mfn, unsigned int cmd, struct vcpu* pt_vcpu, struct domain* pg_dom)
{
    bool preserve_ad = (cmd == MMU_PT_UPDATE_PRESERVE_AD);
    l1_pgentry_t ol1e;
    struct domain* pt_dom = pt_vcpu->domain;
    int rc = 0;
    if (unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0))
        return -EFAULT;

    ASSERT(!paging_mode_refcounts(pt_dom));
    if (l1e_get_flags(nl1e) & _PAGE_PRESENT){
        struct page_info* page = NULL;
        if (unlikely(l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom))){
            gdprintk(XENLOG_WARNING, "Bad L1 flags %x\n", l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom));
            return -EINVAL;
        }
        if (cmd != MMU_PT_UPDATE_NO_TRANSLATE && paging_mode_translate(pg_dom)){
            p2m_type_t p2mt;
            p2m_query_t q = l1e_get_flags(nl1e) & _PAGE_RW ? P2M_ALLOC | P2M_UNSHARE : P2M_ALLOC;
            page = get_page_from_gfn(pg_dom, l1e_get_pfn(nl1e), &p2mt, q);
            if (p2m_is_paged(p2mt)){
                if (page)
                    put_page(page);

                p2m_mem_paging_populate(pg_dom, l1e_get_pfn(nl1e));
                return -ENOENT;
            }
            if (p2mt == p2m_ram_paging_in && !page)
                return -ENOENT;

            if ((q & P2M_UNSHARE) && p2m_is_shared(p2mt)){
                ASSERT(!page);
                return -ENOMEM;
            }
            if (!page)
                return -EINVAL;

            nl1e = l1e_from_page(page, l1e_get_flags(nl1e));
        }
        if (!l1e_has_changed(ol1e, nl1e, ~FASTPATH_FLAG_WHITELIST)){
            nl1e = adjust_guest_l1e(nl1e, pt_dom);
            rc = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                              preserve_ad);
            if (page)
                put_page(page);

            return rc ? 0 : -EBUSY;
        }
        switch (rc = get_page_from_l1e(nl1e, pt_dom, pg_dom)){
            default:
                if (page)
                    put_page(page);

                return rc;
            case 0:
                break;
                case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
                ASSERT(!(rc & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
                l1e_flip_flags(nl1e, rc);
                rc = 0;
                break;
        }
        if (page)
            put_page(page);

        nl1e = adjust_guest_l1e(nl1e, pt_dom);
        if (unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                    preserve_ad))){
            ol1e = nl1e;
            rc = -EBUSY;
        }
    }else
        if (pv_l1tf_check_l1e(pt_dom, nl1e))
            return -ERESTART;
        else
            if (unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                     preserve_ad))){
                return -EBUSY;
            }

    put_page_from_l1e(ol1e, pt_dom);
    return rc;
}

static int mod_l2_entry(l2_pgentry_t* pl2e, l2_pgentry_t nl2e, unsigned long  pfn, int preserve_ad, struct vcpu* vcpu)
{
    l2_pgentry_t ol2e;
    struct domain* d = vcpu->domain;
    struct page_info* l2pg = mfn_to_page(_mfn(pfn));
    unsigned long type = l2pg->u.inuse.type_info;
    int rc = 0;
    if (unlikely(!is_guest_l2_slot(d, type, pgentry_ptr_to_slot(pl2e)))){
        gdprintk(XENLOG_WARNING, "L2 update in Xen-private area, slot %#lx\n", pgentry_ptr_to_slot(pl2e));
        return -EPERM;
    }
    if (unlikely(__copy_from_user(&ol2e, pl2e, sizeof(ol2e)) != 0))
        return -EFAULT;

    if (l2e_get_flags(nl2e) & _PAGE_PRESENT){
        if (unlikely(l2e_get_flags(nl2e) & L2_DISALLOW_MASK)){
            gdprintk(XENLOG_WARNING, "Bad L2 flags %x\n", l2e_get_flags(nl2e) & L2_DISALLOW_MASK);
            return -EINVAL;
        }
        if (!l2e_has_changed(ol2e, nl2e, ~FASTPATH_FLAG_WHITELIST)){
            nl2e = adjust_guest_l2e(nl2e, d);
            if (UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu, preserve_ad))
                return 0;

            return -EBUSY;
        }
        if (unlikely((rc = get_page_from_l2e(nl2e, pfn, d, 0)) < 0))
            return rc;

        nl2e = adjust_guest_l2e(nl2e, d);
        if (unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                    preserve_ad))){
            ol2e = nl2e;
            rc = -EBUSY;
        }
    }else
        if (pv_l1tf_check_l2e(d, nl2e))
            return -ERESTART;
        else
            if (unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                     preserve_ad))){
                return -EBUSY;
            }

    put_page_from_l2e(ol2e, pfn, PTF_defer);
    return rc;
}

static int mod_l3_entry(l3_pgentry_t* pl3e, l3_pgentry_t nl3e, unsigned long  pfn, int preserve_ad, struct vcpu* vcpu)
{
    l3_pgentry_t ol3e;
    struct domain* d = vcpu->domain;
    int rc = 0;
    if (is_pv_32bit_domain(d) && (pgentry_ptr_to_slot(pl3e) >= 3))
        return -EINVAL;

    if (unlikely(__copy_from_user(&ol3e, pl3e, sizeof(ol3e)) != 0))
        return -EFAULT;

    if (l3e_get_flags(nl3e) & _PAGE_PRESENT){
        if (unlikely(l3e_get_flags(nl3e) & l3_disallow_mask(d))){
            gdprintk(XENLOG_WARNING, "Bad L3 flags %x\n", l3e_get_flags(nl3e) & l3_disallow_mask(d));
            return -EINVAL;
        }
        if (!l3e_has_changed(ol3e, nl3e, ~FASTPATH_FLAG_WHITELIST)){
            nl3e = adjust_guest_l3e(nl3e, d);
            rc = UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }
        rc = get_page_from_l3e(nl3e, pfn, d, 0);
        if (unlikely(rc < 0))
            return rc;

        rc = 0;
        nl3e = adjust_guest_l3e(nl3e, d);
        if (unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu,
                                    preserve_ad))){
            ol3e = nl3e;
            rc = -EFAULT;
        }
    }else
        if (pv_l1tf_check_l3e(d, nl3e))
            return -ERESTART;
        else
            if (unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu,
                                     preserve_ad))){
                return -EFAULT;
            }

    if (likely(rc == 0))
        if (!create_pae_xen_mappings(d, pl3e))
            BUG();

    put_page_from_l3e(ol3e, pfn, PTF_defer);
    return rc;
}

static int mod_l4_entry(l4_pgentry_t* pl4e, l4_pgentry_t nl4e, unsigned long  pfn, int preserve_ad, struct vcpu* vcpu)
{
    struct domain* d = vcpu->domain;
    l4_pgentry_t ol4e;
    int rc = 0;
    if (unlikely(!is_guest_l4_slot(d, pgentry_ptr_to_slot(pl4e)))){
        gdprintk(XENLOG_WARNING, "L4 update in Xen-private area, slot %#lx\n", pgentry_ptr_to_slot(pl4e));
        return -EINVAL;
    }
    if (unlikely(__copy_from_user(&ol4e, pl4e, sizeof(ol4e)) != 0))
        return -EFAULT;

    if (l4e_get_flags(nl4e) & _PAGE_PRESENT){
        if (unlikely(l4e_get_flags(nl4e) & L4_DISALLOW_MASK)){
            gdprintk(XENLOG_WARNING, "Bad L4 flags %x\n", l4e_get_flags(nl4e) & L4_DISALLOW_MASK);
            return -EINVAL;
        }
        if (!l4e_has_changed(ol4e, nl4e, ~FASTPATH_FLAG_WHITELIST)){
            nl4e = adjust_guest_l4e(nl4e, d);
            rc = UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }
        rc = get_page_from_l4e(nl4e, pfn, d, 0);
        if (unlikely(rc < 0))
            return rc;

        rc = 0;
        nl4e = adjust_guest_l4e(nl4e, d);
        if (unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu,
                                    preserve_ad))){
            ol4e = nl4e;
            rc = -EFAULT;
        }
    }else
        if (pv_l1tf_check_l4e(d, nl4e))
            return -ERESTART;
        else
            if (unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu,
                                     preserve_ad))){
                return -EFAULT;
            }

    put_page_from_l4e(ol4e, pfn, PTF_defer);
    return rc;
}
static int cleanup_page_mappings(struct page_info* page)
{
    unsigned int cacheattr = (page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base;
    int rc = 0;
    unsigned long mfn = mfn_x(page_to_mfn(page));
    if (unlikely(cacheattr)){
        page->count_info &= ~PGC_cacheattr_mask;
        BUG_ON(is_xen_heap_page(page));
        rc = update_xen_mappings(mfn, 0);
    }
    if ((page->u.inuse.type_info & PGT_type_mask) == PGT_writable_page){
        struct domain* d = page_get_owner(page);
        if (d && is_pv_domain(d) && unlikely(need_iommu_pt_sync(d))){
            int rc2 = iommu_legacy_unmap(d, _dfn(mfn), PAGE_ORDER_4K);
            if (!rc)
                rc = rc2;
        }
        if (likely(!is_xen_heap_page(page))){
            ASSERT((page->u.inuse.type_info &
                    (PGT_type_mask | PGT_count_mask)) == PGT_writable_page);
            if (likely(!rc))
                page->u.inuse.type_info &= ~(PGT_type_mask | PGT_count_mask);
        }
    }
    return rc;
}

void put_page(struct page_info* page)
{
    unsigned long nx, x, y = page->count_info;
    do{
        ASSERT((y & PGC_count_mask) != 0);
        x = y;
        nx = x - 1;
    } while (unlikely((y = cmpxchg(&page->count_info, x, nx)) != x));
    if (unlikely((nx & PGC_count_mask) == 0)){
        if (!cleanup_page_mappings(page))
            free_domheap_page(page);
        else
            gdprintk(XENLOG_WARNING, "Leaking mfn %05lx\n", mfn_x(page_to_mfn(page)));
    }
}

struct domain* page_get_owner_and_reference(struct page_info* page)
{
    unsigned long x, y = page->count_info;
    struct domain* owner;
    do{
        x = y;
        if (unlikely(((x + 2) & PGC_count_mask) <= 2))
            return NULL;
    } while ((y = cmpxchg(&page->count_info, x, x + 1)) != x);
    owner = page_get_owner(page);
    ASSERT(owner);
    return owner;
}

int get_page(struct page_info* page, struct domain* domain)
{
    struct domain* owner = page_get_owner_and_reference(page);
    if (likely(owner == domain))
        return 1;

    if (!paging_mode_refcounts(domain) && !domain->is_dying)
        gprintk(XENLOG_INFO,
                "Error mfn %"PRI_mfn": rd=%d od=%d caf=%08lx taf=%" PRtype_info "\n",
                mfn_x(page_to_mfn(page)), domain->domain_id,
                owner ? owner->domain_id : DOMID_INVALID,
                page->count_info - !!owner, page->u.inuse.type_info);

    if (owner)
        put_page(page);

    return 0;
}

static void get_page_light(struct page_info* page)
{
    unsigned long x, nx, y = page->count_info;
    do{
        x = y;
        nx = x + 1;
        BUG_ON(!(x & PGC_count_mask));
        BUG_ON(!(nx & PGC_count_mask));
        y = cmpxchg(&page->count_info, x, nx);
    } while (unlikely(y != x));
}
static int alloc_page_type(struct page_info* page, unsigned long  type, int preemptible)
{
    struct domain* owner = page_get_owner(page);
    int rc;
    if (likely(owner != NULL))
        paging_mark_dirty(owner, page_to_mfn(page));

    switch (type & PGT_type_mask){
        case PGT_l1_page_table:
            rc = alloc_l1_table(page);
            break;
        case PGT_l2_page_table:
            ASSERT(preemptible);
            rc = alloc_l2_table(page, type);
            break;
        case PGT_l3_page_table:
            ASSERT(preemptible);
            rc = alloc_l3_table(page);
            break;
        case PGT_l4_page_table:
            ASSERT(preemptible);
            rc = alloc_l4_table(page);
            break;
        case PGT_seg_desc_page:
            rc = alloc_segdesc_page(page);
            break;
        default:
            printk("Bad type in alloc_page_type %lx t=%016lx c=%lx\n", type, page->u.inuse.type_info, page->count_info);
            rc = -EINVAL;
            BUG();
    }

    asm("" : : : "memory");
    switch (rc){
        case 0:
            page->u.inuse.type_info |= PGT_validated;
            break;
        case -EINTR:
            ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
            page->u.inuse.type_info &= ~PGT_count_mask;
            break;
        default:
            ASSERT(rc < 0);
            gdprintk(XENLOG_WARNING, "Error while validating mfn %05lx (pfn %05lx) for type %016lx: caf=%08lx taf=%016lx\n", mfn_x(page_to_mfn(page)), get_gpfn_from_mfn(mfn_x(page_to_mfn(page))), type, page->count_info, page->u.inuse.type_info);
            if (page != current->arch.old_guest_table)
                page->u.inuse.type_info = 0;
            else{
                ASSERT((page->u.inuse.type_info &
                    (PGT_count_mask | PGT_validated)) == 1);
            case -ERESTART:
                get_page_light(page);
                page->u.inuse.type_info |= PGT_partial;
        }
        break;
    }
    return rc;
}

int free_page_type(struct page_info* page, unsigned long  type, int preemptible)
{
    struct domain* owner = page_get_owner(page);
    unsigned long gmfn;
    int rc;
    if (likely(owner != NULL) && unlikely(paging_mode_enabled(owner))){
        paging_mark_dirty(owner, page_to_mfn(page));
        ASSERT(!shadow_mode_refcounts(owner));
        gmfn = mfn_to_gmfn(owner, mfn_x(page_to_mfn(page)));
        if (VALID_M2P(gmfn))
            shadow_remove_all_shadows(owner, _mfn(gmfn));
    }
    if (!(type & PGT_partial)){
        page->nr_validated_ptes = 1U << PAGETABLE_ORDER;
        page->partial_flags = 0;
    }
    switch (type & PGT_type_mask){
        case PGT_l1_page_table:
            free_l1_table(page);
            rc = 0;
            break;
        case PGT_l2_page_table:
            ASSERT(preemptible);
            rc = free_l2_table(page);
            break;
        case PGT_l3_page_table:
            ASSERT(preemptible);
            rc = free_l3_table(page);
            break;
        case PGT_l4_page_table:
            ASSERT(preemptible);
            rc = free_l4_table(page);
            break;
        default:
            gdprintk(XENLOG_WARNING, "type %016lx mfn %05lx\n", type, mfn_x(page_to_mfn(page)));
            rc = -EINVAL;
            BUG();
    }
    return rc;
}

static int _put_final_page_type(struct page_info* page, unsigned long  type, bool preemptible, struct page_info* ptpg)
{
    int rc = free_page_type(page, type, preemptible);
    if (ptpg && PGT_type_equal(type, ptpg->u.inuse.type_info) && (type & PGT_validated) && rc != -EINTR){
        dec_linear_uses(page);
        dec_linear_entries(ptpg);
    }
    if (rc == 0){
        ASSERT(!page->linear_pt_count || page_get_owner(page)->is_dying);
        set_tlbflush_timestamp(page);

        asm("" : : : "memory");
        page->u.inuse.type_info--;
    }else
        if (rc == -EINTR){
            ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);

            asm("" : : : "memory");
            page->u.inuse.type_info |= PGT_validated;
        }else{
            BUG_ON(rc != -ERESTART);

            asm("" : : : "memory");
            get_page_light(page);
            page->u.inuse.type_info |= PGT_partial;
        }

    return rc;
}

static int _put_page_type(struct page_info* page, unsigned int flags, struct page_info* ptpg)
{
    unsigned long nx, x, y = page->u.inuse.type_info;
    bool preemptible = flags & PTF_preemptible;
    ASSERT(current_locked_page_ne_check(page));
    for (;;){
        x = y;
        nx = x - 1;
        if (!(flags & PTF_partial_set))
            BUG_ON((x & PGT_partial) ||
                   !((x & PGT_validated) || page_get_owner(page)->is_dying));
        else
            if (!(x & PGT_partial))
                return 0;
            else
                BUG_ON((x & PGT_count_mask) != 1);

        ASSERT((x & PGT_count_mask) != 0);
        switch (nx & (PGT_locked | PGT_count_mask)){
            case 0:
                if (unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) && likely(nx & (PGT_validated|PGT_partial))){
                    int rc;
                    nx = x & ~(PGT_validated | PGT_partial);
                    if (unlikely((y = cmpxchg(&page->u.inuse.type_info,
                                           x, nx)) != x))
                        break;

                    rc = _put_final_page_type(page, x, preemptible, ptpg);
                    if (x & PGT_partial)
                        put_page(page);

                    return rc;
            }
            if (!ptpg || !PGT_type_equal(x, ptpg->u.inuse.type_info)){
                set_tlbflush_timestamp(page);
            }else
                BUG_ON(!IS_ENABLED(CONFIG_PV_LINEAR_PT));

        default:
            if (unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x))
                break;

            if (ptpg && PGT_type_equal(x, ptpg->u.inuse.type_info)){
                dec_linear_uses(page);
                dec_linear_entries(ptpg);
        }
        return 0;
    case PGT_locked:
        ASSERT_UNREACHABLE();
        return -EILSEQ;
    case PGT_locked | 1:
        cpu_relax();
        y = page->u.inuse.type_info;
        break;
}
if (preemptible && hypercall_preempt_check())
    return -EINTR;
}
}

static int _get_page_type(struct page_info* page, unsigned long  type, bool preemptible)
{
unsigned long nx, x, y = page->u.inuse.type_info;
int rc = 0, iommu_ret = 0;
ASSERT(!(type & ~(PGT_type_mask | PGT_pae_xen_l2)));
ASSERT(!in_irq());
for (;;){
x = y;
nx = x + 1;
if (unlikely((nx & PGT_count_mask) == 0)){
    gdprintk(XENLOG_WARNING, "Type count overflow on mfn %05lx\n", mfn_x(page_to_mfn(page)));
    return -EINVAL;
}else
    if (unlikely((x & PGT_count_mask) == 0)){
        struct domain* d = page_get_owner(page);
        if (d && shadow_mode_enabled(d))
            shadow_prepare_page_type_change(d, page, type);

        ASSERT(!(x & PGT_pae_xen_l2));
        if ((x & PGT_type_mask) != type){
            cpumask_t* mask = this_cpu(scratch_cpumask);
            BUG_ON(in_irq());
            cpumask_copy(mask, d->dirty_cpumask);
            tlbflush_filter(mask, page->tlbflush_timestamp);
            if (unlikely(!cpumask_empty(mask)) && (!shadow_mode_enabled(page_get_owner(page)) || ((nx & PGT_type_mask) == PGT_writable_page))){
                perfc_incr(need_flush_tlb_flush);
                flush_tlb_mask(mask);
            }
            nx &= ~(PGT_type_mask | PGT_validated);
            nx |= type;
            if (type == PGT_writable_page || type == PGT_shared_page)
                nx |= PGT_validated;
        }
    }else
        if (unlikely((x & (PGT_type_mask|PGT_pae_xen_l2)) != type)){
            if (((x & PGT_type_mask) == PGT_l2_page_table) && (type == PGT_l1_page_table))
                return -EINVAL;

            if (((x & PGT_type_mask) == PGT_l3_page_table) && (type == PGT_l2_page_table))
                return -EINVAL;

            if (((x & PGT_type_mask) == PGT_l4_page_table) && (type == PGT_l3_page_table))
                return -EINVAL;

            gdprintk(XENLOG_WARNING, "Bad type (saw %016lx != exp %016lx) for mfn %05lx (pfn %05lx)\n", x, type, mfn_x(page_to_mfn(page)), get_gpfn_from_mfn(mfn_x(page_to_mfn(page))));
            return -EINVAL;
        }else
            if (unlikely(!(x & PGT_validated))){
                if (!(x & PGT_partial)){
                    do{
                        if (preemptible && hypercall_preempt_check())
                            return -EINTR;

                        cpu_relax();
                    } while ((y = page->u.inuse.type_info) == x);
                    continue;
                }
                ASSERT((x & PGT_count_mask) == 1);
                nx = x & ~PGT_partial;
            }

if (likely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) == x))
    break;

if (preemptible && hypercall_preempt_check())
    return -EINTR;
}
if (unlikely((x & PGT_type_mask) != type)){
struct domain* d = page_get_owner(page);
if (d && is_pv_domain(d) && unlikely(need_iommu_pt_sync(d))){
    mfn_t mfn = page_to_mfn(page);
    if ((x & PGT_type_mask) == PGT_writable_page)
        iommu_ret = iommu_legacy_unmap(d, _dfn(mfn_x(mfn)), PAGE_ORDER_4K);
    else
        if (type == PGT_writable_page)
            iommu_ret = iommu_legacy_map(d, _dfn(mfn_x(mfn)), mfn, PAGE_ORDER_4K, IOMMUF_readable | IOMMUF_writable);

    if (unlikely(iommu_ret)){
        _put_page_type(page, 0, NULL);
        rc = iommu_ret;
        goto out;
    }
}
}
if (unlikely(!(nx & PGT_validated))){
if (!(x & PGT_partial)){
    page->nr_validated_ptes = 0;
    page->partial_flags = 0;
    page->linear_pt_count = 0;
}
rc = alloc_page_type(page, type, preemptible);
}
out:
if ((x & PGT_partial) && !(nx & PGT_partial))
put_page(page);
return rc;
}

void put_page_type(struct page_info* page)
{
int rc = _put_page_type(page, 0, NULL);
ASSERT(rc == 0);
(void)(rc);
}
int get_page_type(struct page_info* page, unsigned long  type)
{
int rc = _get_page_type(page, type, false);
if (likely(rc == 0))
    return 1;

ASSERT(rc != -EINTR && rc != -ERESTART);
return 0;
}

int put_page_type_preemptible(struct page_info* page)
{
return _put_page_type(page, PTF_preemptible, NULL);
}
int get_page_type_preemptible(struct page_info* page, unsigned long  type)
{
ASSERT(!current->arch.old_guest_table);
return _get_page_type(page, type, true);
}

int put_old_guest_table(struct vcpu* v)
{
int rc;
if (!v->arch.old_guest_table)
    return 0;

rc = _put_page_type(v->arch.old_guest_table, PTF_preemptible | (v->arch.old_guest_table_partial ? PTF_partial_set : 0), v->arch.old_guest_ptpg);
if (rc == -ERESTART || rc == -EINTR){
    v->arch.old_guest_table_partial = (rc == -ERESTART);
    return -ERESTART;
}
ASSERT(rc == 0);
put_page(v->arch.old_guest_table);
v->arch.old_guest_table = NULL;
v->arch.old_guest_ptpg = NULL;
v->arch.old_guest_table_partial = true;
return rc;
}

int vcpu_destroy_pagetables(struct vcpu* v)
{
unsigned long mfn = pagetable_get_pfn(v->arch.guest_table);
struct page_info* page = NULL;
int rc = put_old_guest_table(v);
bool put_guest_table_user = false;
if (rc)
    return rc;

v->arch.cr3 = 0;
if (is_pv_32bit_vcpu(v)){
    l4_pgentry_t* l4tab = map_domain_page(_mfn(mfn));
    mfn = l4e_get_pfn(*l4tab);
    l4e_write(l4tab, l4e_empty());
    unmap_domain_page(l4tab);
}else{
    v->arch.guest_table = pagetable_null();
    put_guest_table_user = true;
}
do{
    if (mfn){
        page = mfn_to_page(_mfn(mfn));
        if (paging_mode_refcounts(v->domain))
            put_page(page);
        else
            rc = put_page_and_type_preemptible(page);

        mfn = 0;
    }
    if (!rc && put_guest_table_user){
        mfn = pagetable_get_pfn(v->arch.guest_table_user);
        v->arch.guest_table_user = pagetable_null();
        put_guest_table_user = false;
    }
} while (mfn);
switch (rc){
    case -EINTR:
    case -ERESTART:
        v->arch.old_guest_ptpg = NULL;
        v->arch.old_guest_table = page;
        v->arch.old_guest_table_partial = (rc == -ERESTART);
        rc = -ERESTART;
        break;
    default:
        ASSERT(rc == 0);
        break;
}
return rc;
}

int new_guest_cr3(mfn_t mfn)
{
struct vcpu* curr = current;
struct domain* d = curr->domain;
int rc;
mfn_t old_base_mfn;
if (is_pv_32bit_domain(d)){
    mfn_t gt_mfn = pagetable_get_mfn(curr->arch.guest_table);
    l4_pgentry_t* pl4e = map_domain_page(gt_mfn);
    rc = mod_l4_entry(pl4e, l4e_from_mfn(mfn,
                                       (_PAGE_PRESENT | _PAGE_RW |
                                        _PAGE_USER | _PAGE_ACCESSED)), mfn_x(gt_mfn), 0, curr);
    unmap_domain_page(pl4e);
    switch (rc){
        case 0:
            break;
        case -EINTR:
        case -ERESTART:
            return -ERESTART;
        default:
            gdprintk(XENLOG_WARNING, "Error while installing new compat baseptr %05lx\n", mfn_x(mfn));
            return rc;
    }
    pv_destroy_ldt(curr);
    write_ptbase(curr);
    return 0;
}
rc = put_old_guest_table(curr);
if (unlikely(rc))
    return rc;

old_base_mfn = pagetable_get_mfn(curr->arch.guest_table);
if (mfn_eq(old_base_mfn, mfn)){
    write_ptbase(curr);
    return 0;
}
rc = get_page_and_type_from_mfn(mfn, PGT_root_page_table, d, PTF_preemptible);
switch (rc){
    case 0:
        break;
    case -EINTR:
    case -ERESTART:
        return -ERESTART;
    default:
        gdprintk(XENLOG_WARNING, "Error while installing new baseptr %05lx\n", mfn_x(mfn));
        return rc;
}
pv_destroy_ldt(curr);
if ( !VM_ASSIST(d, m2p_strict) && !paging_mode_refcounts(d) )
        fill_ro_mpt(mfn);

curr->arch.guest_table = pagetable_from_mfn(mfn);
update_cr3(curr);
write_ptbase(curr);
if (likely(mfn_x(old_base_mfn) != 0)){
    struct page_info* page = mfn_to_page(old_base_mfn);
    if (paging_mode_refcounts(d))
        put_page(page);
    else
        switch (rc = put_page_and_type_preemptible(page)){
            case -EINTR:
            case -ERESTART:
                curr->arch.old_guest_ptpg = NULL;
                curr->arch.old_guest_table = page;
                curr->arch.old_guest_table_partial = (rc == -ERESTART);
                rc = -ERESTART;
                break;
            default:
                BUG_ON(rc);
                break;
        }
}
return rc;
}

static int vcpumask_to_pcpumask(struct domain* d, XEN_GUEST_HANDLE_PARAM(const_void) bmap, cpumask_t* pmask)
{
unsigned int vcpu_id, vcpu_bias, offs;
unsigned long vmask;
struct vcpu* v;
bool is_native = !is_pv_32bit_domain(d);
cpumask_clear(pmask);
for (vmask = 0, offs = 0;;++offs){
    vcpu_bias = offs * (is_native ? BITS_PER_LONG : 32);
    if (vcpu_bias >= d->max_vcpus)
        return 0;

    if (unlikely(is_native ?
                      copy_from_guest_offset(&vmask, bmap, offs, 1) :
                      copy_from_guest_offset((unsigned int *)&vmask, bmap,
                                             offs, 1))){
        cpumask_clear(pmask);
        return -EFAULT;
    }
    while (vmask){
        unsigned int cpu;
        vcpu_id = find_first_set_bit(vmask);
        vmask &= ~(1UL << vcpu_id);
        vcpu_id += vcpu_bias;
        if ((vcpu_id >= d->max_vcpus))
            return 0;

        if ((v = d->vcpu[vcpu_id]) == NULL)
            continue;

        cpu = read_atomic(&v->dirty_cpu);
        if (is_vcpu_dirty_cpu(cpu))
            __cpumask_set_cpu(cpu, pmask);
    }
}
}

long do_mmuext_op(XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone, unsigned int foreigndom)
{
struct mmuext_op op;
unsigned long type;
unsigned int i, done = 0;
struct vcpu* curr = current;
struct domain* currd = curr->domain;
struct domain* pg_owner;
int rc = put_old_guest_table(curr);
if (unlikely(rc)){
    if (likely(rc == -ERESTART))
        rc = hypercall_create_continuation(__HYPERVISOR_mmuext_op, "hihi", uops, count, pdone, foreigndom);

    return rc;
}
if ( unlikely(count == MMU_UPDATE_PREEMPTED) &&
         likely(guest_handle_is_null(uops)) )
    {
        /*
         * See the curr->arch.old_guest_table related
         * hypercall_create_continuation() below.
         */
        return (int)foreigndom;
    }
if (unlikely(count & MMU_UPDATE_PREEMPTED)){
    count &= ~MMU_UPDATE_PREEMPTED;
    if (unlikely(!guest_handle_is_null(pdone)))
        (void)(copy_from_guest(&done, pdone, 1));
}else
    perfc_incr(calls_to_mmuext_op);

if (unlikely(!guest_handle_okay(uops, count)))
    return -EFAULT;

if ((pg_owner = get_pg_owner(foreigndom)) == NULL)
    return -ESRCH;

if (!is_pv_domain(pg_owner)){
    put_pg_owner(pg_owner);
    return -EINVAL;
}
rc = xsm_mmuext_op(XSM_TARGET, currd, pg_owner);
if (rc){
    put_pg_owner(pg_owner);
    return rc;
}
for (i = 0;i < count;i++){
    if (curr->arch.old_guest_table || (i && hypercall_preempt_check())){
        rc = -ERESTART;
        break;
    }
    if (unlikely(__copy_from_guest(&op, uops, 1) != 0)){
        rc = -EFAULT;
        break;
    }
    if (is_hvm_domain(currd)){
        switch (op.cmd){
            case MMUEXT_PIN_L1_TABLE:
            case MMUEXT_PIN_L2_TABLE:
            case MMUEXT_PIN_L3_TABLE:
            case MMUEXT_PIN_L4_TABLE:
            case MMUEXT_UNPIN_TABLE:
                break;
            default:
                rc = -EOPNOTSUPP;
                goto done;
        }
    }
    rc = 0;
    switch (op.cmd){
        struct page_info* page;
        p2m_type_t p2mt;
        case MMUEXT_PIN_L1_TABLE:
            type = PGT_l1_page_table;
            goto pin_page;
        case MMUEXT_PIN_L2_TABLE:
            type = PGT_l2_page_table;
            goto pin_page;
        case MMUEXT_PIN_L3_TABLE:
            type = PGT_l3_page_table;
            goto pin_page;
        case MMUEXT_PIN_L4_TABLE:
            if (is_pv_32bit_domain(pg_owner))
                break;

            type = PGT_l4_page_table;
            pin_page:
            if ((op.cmd - MMUEXT_PIN_L1_TABLE) > (CONFIG_PAGING_LEVELS - 1))
                break;
            if (paging_mode_refcounts(pg_owner))
                break;

            page = get_page_from_gfn(pg_owner, op.arg1.mfn, NULL, P2M_ALLOC);
            if (unlikely(!page)){
                rc = -EINVAL;
                break;
        }
        rc = get_page_type_preemptible(page, type);
        if (unlikely(rc)){
            if (rc == -EINTR)
                rc = -ERESTART;
            else
                if (rc != -ERESTART)
                    gdprintk(XENLOG_WARNING, "Error %d while pinning mfn %05lx\n", rc, mfn_x(page_to_mfn(page)));

            if (page != curr->arch.old_guest_table)
                put_page(page);

            break;
        }
        rc = xsm_memory_pin_page(XSM_HOOK, currd, pg_owner, page);
        if (!rc && unlikely(test_and_set_bit(_PGT_pinned,
                                                  &page->u.inuse.type_info))){
            gdprintk(XENLOG_WARNING, "mfn %05lx already pinned\n", mfn_x(page_to_mfn(page)));
            rc = -EINVAL;
        }
        if (unlikely(rc))
            goto pin_drop;

        paging_mark_dirty(pg_owner, page_to_mfn(page));
        if (unlikely(pg_owner != currd)){
            bool drop_ref;
            spin_lock(&pg_owner->page_alloc_lock);
            drop_ref = (pg_owner->is_dying && test_and_clear_bit(_PGT_pinned,
                                               &page->u.inuse.type_info));
            spin_unlock(&pg_owner->page_alloc_lock);
            if (drop_ref){
                pin_drop:
                if (type == PGT_l1_page_table)
                    put_page_and_type(page);
                else{
                    curr->arch.old_guest_ptpg = NULL;
                    curr->arch.old_guest_table = page;
                    curr->arch.old_guest_table_partial = false;
                }
            }
        }
        break;
    case MMUEXT_UNPIN_TABLE:
        if (paging_mode_refcounts(pg_owner))
            break;

        page = get_page_from_gfn(pg_owner, op.arg1.mfn, NULL, P2M_ALLOC);
        if (unlikely(!page)){
            gdprintk(XENLOG_WARNING, "mfn %05lx bad, or bad owner d%d\n", op.arg1.mfn, pg_owner->domain_id);
            rc = -EINVAL;
            break;
    }
    if (!test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info)){
        put_page(page);
        gdprintk(XENLOG_WARNING, "mfn %05lx not pinned\n", op.arg1.mfn);
        rc = -EINVAL;
        break;
    }
    switch (rc = put_page_and_type_preemptible(page)){
        case -EINTR:
        case -ERESTART:
            curr->arch.old_guest_ptpg = NULL;
            curr->arch.old_guest_table = page;
            curr->arch.old_guest_table_partial = (rc == -ERESTART);
            rc = 0;
            break;
        default:
            BUG_ON(rc);
            break;
    }
    put_page(page);
    paging_mark_dirty(pg_owner, page_to_mfn(page));
    break;
case MMUEXT_NEW_BASEPTR:
    if (unlikely(currd != pg_owner))
        rc = -EPERM;
    else
        if (unlikely(paging_mode_translate(currd)))
            rc = -EINVAL;
        else
            rc = new_guest_cr3(_mfn(op.arg1.mfn));

    break;
case MMUEXT_NEW_USER_BASEPTR:
    {
        unsigned long old_mfn;
        if (unlikely(currd != pg_owner))
            rc = -EPERM;
        else
            if (unlikely(paging_mode_translate(currd)))
                rc = -EINVAL;

        if (unlikely(rc))
            break;

        old_mfn = pagetable_get_pfn(curr->arch.guest_table_user);
        if (old_mfn == op.arg1.mfn)
            break;

        if (op.arg1.mfn != 0){
            rc = get_page_and_type_from_mfn(_mfn(op.arg1.mfn), PGT_root_page_table, currd, PTF_preemptible);
            if (unlikely(rc)){
                if (rc == -EINTR)
                    rc = -ERESTART;
                else
                    if (rc != -ERESTART)
                        gdprintk(XENLOG_WARNING, "Error %d installing new mfn %05lx\n", rc, op.arg1.mfn);

                break;
        }
        if (VM_ASSIST(currd, m2p_strict))
            zap_ro_mpt(_mfn(op.arg1.mfn));
    }
    curr->arch.guest_table_user = pagetable_from_pfn(op.arg1.mfn);
    if (old_mfn != 0){
        page = mfn_to_page(_mfn(old_mfn));
        switch (rc = put_page_and_type_preemptible(page)){
            case -EINTR:
            case -ERESTART:
                curr->arch.old_guest_ptpg = NULL;
                curr->arch.old_guest_table = page;
                curr->arch.old_guest_table_partial = (rc == -ERESTART);
                rc = -ERESTART;
                break;
            default:
                BUG_ON(rc);
                break;
        }
    }
    break;
}case MMUEXT_TLB_FLUSH_LOCAL:
    if (likely(currd == pg_owner))
        flush_tlb_local();
    else
        rc = -EPERM;

    break;
case MMUEXT_INVLPG_LOCAL:
    if (unlikely(currd != pg_owner))
        rc = -EPERM;
    else
        paging_invlpg(curr, op.arg1.linear_addr);

    break;
case MMUEXT_TLB_FLUSH_MULTI:
case MMUEXT_INVLPG_MULTI:
    {
        cpumask_t* mask = this_cpu(scratch_cpumask);
        if (unlikely(currd != pg_owner))
            rc = -EPERM;
        else
            if (unlikely(vcpumask_to_pcpumask(currd,
                                   guest_handle_to_param(op.arg2.vcpumask,
                                                         const_void),
                                   mask)))
                rc = -EINVAL;

        if (unlikely(rc))
            break;

        if (op.cmd == MMUEXT_TLB_FLUSH_MULTI)
            flush_tlb_mask(mask);
        else
            if (__addr_ok(op.arg1.linear_addr))
                flush_tlb_one_mask(mask, op.arg1.linear_addr);

        break;
}case MMUEXT_TLB_FLUSH_ALL:
    if (likely(currd == pg_owner))
        flush_tlb_mask(currd->dirty_cpumask);
    else
        rc = -EPERM;

    break;
case MMUEXT_INVLPG_ALL:
    if (unlikely(currd != pg_owner))
        rc = -EPERM;
    else
        if (__addr_ok(op.arg1.linear_addr))
            flush_tlb_one_mask(currd->dirty_cpumask, op.arg1.linear_addr);

    break;
case MMUEXT_FLUSH_CACHE:
    if (unlikely(currd != pg_owner))
        rc = -EPERM;
    else
        if (unlikely(!cache_flush_permitted(currd)))
            rc = -EACCES;
        else

            asm("wbinvd" : : : "memory");

    break;
case MMUEXT_FLUSH_CACHE_GLOBAL:
    if (unlikely(currd != pg_owner))
        rc = -EPERM;
    else
        if (likely(cache_flush_permitted(currd))){
            unsigned int cpu;
            cpumask_t* mask = this_cpu(scratch_cpumask);
            cpumask_clear(mask);
            for_each_online_cpu(cpu)
                if (!cpumask_intersects(mask, per_cpu(cpu_sibling_mask, cpu)))
                    __cpumask_set_cpu(cpu, mask);
            flush_mask(mask, FLUSH_CACHE);
    }else
        rc = -EINVAL;

break;
case MMUEXT_SET_LDT:
    {
        unsigned int ents = op.arg2.nr_ents;
        unsigned long ptr = ents ? op.arg1.linear_addr : 0;
        if (unlikely(currd != pg_owner))
            rc = -EPERM;
        else
            if (paging_mode_external(currd))
                rc = -EINVAL;
            else
                if (((ptr & (PAGE_SIZE - 1)) != 0) || !__addr_ok(ptr) || (ents > 8192)){
                    gdprintk(XENLOG_WARNING, "Bad args to SET_LDT: ptr=%lx, ents=%x\n", ptr, ents);
                    rc = -EINVAL;
            }else
                if ((curr->arch.pv.ldt_ents != ents) || (curr->arch.pv.ldt_base != ptr)){
                    if (pv_destroy_ldt(curr))
                        flush_tlb_local();

                    curr->arch.pv.ldt_base = ptr;
                    curr->arch.pv.ldt_ents = ents;
                    load_LDT(curr);
                }

    break;
}case MMUEXT_CLEAR_PAGE:
    page = get_page_from_gfn(pg_owner, op.arg1.mfn, &p2mt, P2M_ALLOC);
    if (unlikely(p2mt != p2m_ram_rw) && page){
        put_page(page);
        page = NULL;
}
if (!page || !get_page_type(page, PGT_writable_page)){
    if (page)
        put_page(page);

    gdprintk(XENLOG_WARNING, "Error clearing mfn %05lx\n", op.arg1.mfn);
    rc = -EINVAL;
    break;
}
paging_mark_dirty(pg_owner, page_to_mfn(page));
clear_domain_page(page_to_mfn(page));
put_page_and_type(page);
break;
case MMUEXT_COPY_PAGE:
    {
        struct page_info *src_page, *dst_page;
        src_page = get_page_from_gfn(pg_owner, op.arg2.src_mfn, &p2mt, P2M_ALLOC);
        if (unlikely(p2mt != p2m_ram_rw) && src_page){
            put_page(src_page);
            src_page = NULL;
    }
    if (unlikely(!src_page)){
        gdprintk(XENLOG_WARNING, "Error copying from mfn %05lx\n", op.arg2.src_mfn);
        rc = -EINVAL;
        break;
    }
    dst_page = get_page_from_gfn(pg_owner, op.arg1.mfn, &p2mt, P2M_ALLOC);
    if (unlikely(p2mt != p2m_ram_rw) && dst_page){
        put_page(dst_page);
        dst_page = NULL;
    }
    rc = (dst_page && get_page_type(dst_page, PGT_writable_page)) ? 0 : -EINVAL;
    if (unlikely(rc)){
        put_page(src_page);
        if (dst_page)
            put_page(dst_page);

        gdprintk(XENLOG_WARNING, "Error copying to mfn %05lx\n", op.arg1.mfn);
        break;
    }
    paging_mark_dirty(pg_owner, page_to_mfn(dst_page));
    copy_domain_page(page_to_mfn(dst_page), page_to_mfn(src_page));
    put_page_and_type(dst_page);
    put_page(src_page);
    break;
}
case MMUEXT_MARK_SUPER:
case MMUEXT_UNMARK_SUPER:
    rc = -EOPNOTSUPP;
    break;
default:
    rc = -ENOSYS;
    break;
}
done:
if (unlikely(rc))
break;
guest_handle_add_offset(uops, 1);
}
if (rc == -ERESTART)
rc = hypercall_create_continuation(__HYPERVISOR_mmuext_op, "hihi", uops, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
else
    if (curr->arch.old_guest_table){
        XEN_GUEST_HANDLE_PARAM(void) null;
        ASSERT(rc || i == count);
        set_xen_guest_handle(null, NULL);
        rc = hypercall_create_continuation(__HYPERVISOR_mmuext_op, "hihi", null, MMU_UPDATE_PREEMPTED, null, rc);
    }

put_pg_owner(pg_owner);
perfc_add(num_mmuext_ops, i);
if (unlikely(!guest_handle_is_null(pdone))){
    done += i;
    copy_to_guest(pdone, &done, 1);
}
return rc;
}

long do_mmu_update(XEN_GUEST_HANDLE_PARAM(mmu_update_t) ureqs, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone, unsigned int foreigndom)
{
struct mmu_update req;
void* va = NULL;
unsigned long gpfn, gmfn, mfn;
struct page_info* page;
unsigned int cmd, i = 0, done = 0, pt_dom;
struct vcpu *curr = current, *v = curr;
struct domain *d = v->domain, *pt_owner = d, *pg_owner;
mfn_t map_mfn = INVALID_MFN;
bool sync_guest = false;
uint32_t xsm_needed = 0;
uint32_t xsm_checked = 0;
int rc = put_old_guest_table(curr);
if (unlikely(rc)){
    if (likely(rc == -ERESTART))
        rc = hypercall_create_continuation(__HYPERVISOR_mmu_update, "hihi", ureqs, count, pdone, foreigndom);

    return rc;
}
if ( unlikely(count == MMU_UPDATE_PREEMPTED) &&
         likely(guest_handle_is_null(ureqs)) )
    {
        /*
         * See the curr->arch.old_guest_table related
         * hypercall_create_continuation() below.
         */
        return (int)foreigndom;
    }
if (unlikely(count & MMU_UPDATE_PREEMPTED)){
    count &= ~MMU_UPDATE_PREEMPTED;
    if (unlikely(!guest_handle_is_null(pdone)))
        (void)(copy_from_guest(&done, pdone, 1));
}else
    perfc_incr(calls_to_mmu_update);

if (unlikely(!guest_handle_okay(ureqs, count)))
    return -EFAULT;

if ((pt_dom = foreigndom >> 16) != 0){
    if ((pt_owner = rcu_lock_domain_by_id(pt_dom - 1)) == NULL)
        return -ESRCH;

    if (pt_owner == d)
        rcu_unlock_domain(pt_owner);
    else
        if (!pt_owner->vcpu || (v = pt_owner->vcpu[0]) == NULL){
            rc = -EINVAL;
            goto out;
        }
}
if ((pg_owner = get_pg_owner((uint16_t)(foreigndom))) == NULL){
    rc = -ESRCH;
    goto out;
}
for (i = 0;i < count;i++){
    if (curr->arch.old_guest_table || (i && hypercall_preempt_check())){
        rc = -ERESTART;
        break;
    }
    if (unlikely(__copy_from_guest(&req, ureqs, 1) != 0)){
        rc = -EFAULT;
        break;
    }
    cmd = req.ptr & (sizeof (l1_pgentry_t) - 1);
    switch (cmd){
        case MMU_NORMAL_PT_UPDATE:
        case MMU_PT_UPDATE_PRESERVE_AD:
        case MMU_PT_UPDATE_NO_TRANSLATE:
            {
                p2m_type_t p2mt;
                rc = -EOPNOTSUPP;
                if (unlikely(paging_mode_refcounts(pt_owner)))
                    break;

                xsm_needed |= XSM_MMU_NORMAL_UPDATE;
                if (get_pte_flags(req.val) & _PAGE_PRESENT){
                    xsm_needed |= XSM_MMU_UPDATE_READ;
                    if (get_pte_flags(req.val) & _PAGE_RW)
                        xsm_needed |= XSM_MMU_UPDATE_WRITE;
            }
            if (xsm_needed != xsm_checked){
                rc = xsm_mmu_update(XSM_TARGET, d, pt_owner, pg_owner, xsm_needed);
                if (rc)
                    break;

                xsm_checked = xsm_needed;
            }
            rc = -EINVAL;
            req.ptr -= cmd;
            gmfn = req.ptr >> PAGE_SHIFT;
            page = get_page_from_gfn(pt_owner, gmfn, &p2mt, P2M_ALLOC);
            if (unlikely(!page) || p2mt != p2m_ram_rw){
                if (page)
                    put_page(page);

                if (p2m_is_paged(p2mt)){
                    p2m_mem_paging_populate(pt_owner, gmfn);
                    rc = -ENOENT;
                }else
                    gdprintk(XENLOG_WARNING, "Could not get page for normal update\n");

                break;
            }
            mfn = mfn_x(page_to_mfn(page));
            if (!mfn_eq(_mfn(mfn), map_mfn)){
                if (va)
                    unmap_domain_page(va);

                va = map_domain_page(_mfn(mfn));
                map_mfn = _mfn(mfn);
            }
            va = _p(((unsigned long)va & PAGE_MASK) + (req.ptr & ~PAGE_MASK));
            if (page_lock(page)){
                switch (page->u.inuse.type_info & PGT_type_mask){
                    case PGT_l1_page_table:
                        rc = mod_l1_entry(va, l1e_from_intpte(req.val), mfn, cmd, v, pg_owner);
                        break;
                    case PGT_l2_page_table:
                        if (unlikely(pg_owner != pt_owner))
                            break;

                        rc = mod_l2_entry(va, l2e_from_intpte(req.val), mfn, cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                        break;
                    case PGT_l3_page_table:
                        if (unlikely(pg_owner != pt_owner))
                            break;

                        rc = mod_l3_entry(va, l3e_from_intpte(req.val), mfn, cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                        break;
                    case PGT_l4_page_table:
                        if (unlikely(pg_owner != pt_owner))
                            break;

                        rc = mod_l4_entry(va, l4e_from_intpte(req.val), mfn, cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                        if (!rc && pt_owner->arch.pv.xpti){
                            bool local_in_use = false;
                            if (pagetable_get_pfn(curr->arch.guest_table) == mfn){
                                local_in_use = true;
                                get_cpu_info()->root_pgt_changed = true;
                        }
                        if ((page->u.inuse.type_info & PGT_count_mask) > (1 + !!(page->u.inuse.type_info & PGT_pinned) + (pagetable_get_pfn(curr->arch.guest_table_user) == mfn) + local_in_use))
                            sync_guest = true;
                    }
                    break;
                case PGT_writable_page:
                    perfc_incr(writable_mmu_updates);
                    if (paging_write_guest_entry(v, va, req.val, _mfn(mfn)))
                        rc = 0;

                    break;
            }
            page_unlock(page);
            if (rc == -EINTR)
                rc = -ERESTART;
        }else
            if (get_page_type(page, PGT_writable_page)){
                perfc_incr(writable_mmu_updates);
                if (paging_write_guest_entry(v, va, req.val, _mfn(mfn)))
                    rc = 0;

                put_page_type(page);
            }

        put_page(page);
    }
    break;
case MMU_MACHPHYS_UPDATE:
    if (unlikely(d != pt_owner)){
        rc = -EPERM;
        break;
}
if (unlikely(paging_mode_translate(pg_owner))){
    rc = -EINVAL;
    break;
}
mfn = req.ptr >> PAGE_SHIFT;
gpfn = req.val;
xsm_needed |= XSM_MMU_MACHPHYS_UPDATE;
if (xsm_needed != xsm_checked){
    rc = xsm_mmu_update(XSM_TARGET, d, NULL, pg_owner, xsm_needed);
    if (rc)
        break;

    xsm_checked = xsm_needed;
}
page = get_page_from_mfn(_mfn(mfn), pg_owner);
if (unlikely(!page)){
    gdprintk(XENLOG_WARNING, "Could not get page for mach->phys update\n");
    rc = -EINVAL;
    break;
}
set_gpfn_from_mfn(mfn, gpfn);
paging_mark_pfn_dirty(pg_owner, _pfn(gpfn));
put_page(page);
break;
default:
    rc = -ENOSYS;
    break;
}
if (unlikely(rc))
break;

guest_handle_add_offset(ureqs, 1);
}
if (rc == -ERESTART)
rc = hypercall_create_continuation(__HYPERVISOR_mmu_update, "hihi", ureqs, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
else
    if (curr->arch.old_guest_table){
        XEN_GUEST_HANDLE_PARAM(void) null;
        ASSERT(rc || i == count);
        set_xen_guest_handle(null, NULL);
        rc = hypercall_create_continuation(__HYPERVISOR_mmu_update, "hihi", null, MMU_UPDATE_PREEMPTED, null, rc);
    }

put_pg_owner(pg_owner);
if (va)
    unmap_domain_page(va);

if (sync_guest){
    unsigned int cpu = smp_processor_id();
    cpumask_t* mask = per_cpu(scratch_cpumask, cpu);
    cpumask_andnot(mask, pt_owner->dirty_cpumask, cpumask_of(cpu));
    if (!cpumask_empty(mask))
        flush_mask(mask, FLUSH_TLB_GLOBAL | FLUSH_ROOT_PGTBL);
}
perfc_add(num_page_updates, i);
out:
if (pt_owner != d)
    rcu_unlock_domain(pt_owner);
if (unlikely(!guest_handle_is_null(pdone))){
    done += i;
    copy_to_guest(pdone, &done, 1);
}
return rc;
}

int donate_page(struct domain* d, struct page_info* page, unsigned int memflags)
{
const struct domain* owner = dom_xen;
spin_lock(&d->page_alloc_lock);
if ( is_xen_heap_page(page) || ((owner = page_get_owner(page)) != NULL) )
        goto fail;

if (d->is_dying)
    goto fail;

if (page->count_info & ~(PGC_allocated | 1))
    goto fail;

if (!(memflags & MEMF_no_refcount)){
    if (d->tot_pages >= d->max_pages)
        goto fail;

    if (unlikely(domain_adjust_tot_pages(d, 1) == 1))
        get_knownalive_domain(d);
}
page->count_info = PGC_allocated | 1;
page_set_owner(page, d);
page_list_add_tail(page, &d->page_list);
spin_unlock(&d->page_alloc_lock);
return 0;
fail:
spin_unlock(&d->page_alloc_lock);
gdprintk(XENLOG_WARNING, "Bad donate mfn %05lx to d%d (owner d%d) caf=%08lx taf=%016lx\n", mfn_x(page_to_mfn(page)), d->domain_id, owner ? owner->domain_id : DOMID_INVALID, page->count_info, page->u.inuse.type_info);
return -EINVAL;
}

int steal_page(struct domain* d, struct page_info* page, unsigned int memflags)
{
unsigned long x, y;
bool drop_dom_ref = false;
const struct domain* owner;
int rc;
if (paging_mode_external(d))
    return -EOPNOTSUPP;

rc = -EINVAL;
if (!(owner = page_get_owner_and_reference(page)))
    goto fail;

if (owner != d || is_xen_heap_page(page))
    goto fail_put;

y = page->count_info;
do{
    x = y;
    if ((x & (PGC_count_mask | PGC_allocated)) != (2 | PGC_allocated))
        goto fail_put;

    y = cmpxchg(&page->count_info, x, x & ~(PGC_count_mask|PGC_allocated));
} while (y != x);
if ((rc = cleanup_page_mappings(page))){
    page->count_info |= PGC_allocated | 1;
    goto fail;
}
spin_lock(&d->page_alloc_lock);
BUG_ON(page->u.inuse.type_info & (PGT_count_mask | PGT_locked |
                                      PGT_pinned));
page->u.inuse.type_info = 0;
page_set_owner(page, NULL);
page_list_del(page, &d->page_list);
if (!(memflags & MEMF_no_refcount) && !domain_adjust_tot_pages(d, -1))
    drop_dom_ref = true;

spin_unlock(&d->page_alloc_lock);
if (unlikely(drop_dom_ref))
    put_domain(d);

return 0;
fail_put:
put_page(page);
fail:
gdprintk(XENLOG_WARNING, "Bad steal mfn %05lx from d%d (owner d%d) caf=%08lx taf=%016lx\n", mfn_x(page_to_mfn(page)), d->domain_id, owner ? owner->domain_id : DOMID_INVALID, page->count_info, page->u.inuse.type_info);
return rc;
}

static int __do_update_va_mapping(unsigned long  va, u64 val64, unsigned long  flags, struct domain* pg_owner)
{
l1_pgentry_t val = l1e_from_intpte(val64);
struct vcpu* v = current;
struct domain* d = v->domain;
struct page_info* gl1pg;
l1_pgentry_t* pl1e;
unsigned long bmap_ptr;
mfn_t gl1mfn;
cpumask_t* mask = NULL;
int rc;
perfc_incr(calls_to_update_va);
rc = xsm_update_va_mapping(XSM_TARGET, d, pg_owner, val);
if (rc)
    return rc;

rc = -EINVAL;
pl1e = map_guest_l1e(va, &gl1mfn);
gl1pg = pl1e ? get_page_from_mfn(gl1mfn, d) : NULL;
if (unlikely(!gl1pg))
    goto out;

if (!page_lock(gl1pg)){
    put_page(gl1pg);
    goto out;
}
if ( (gl1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(gl1pg);
        put_page(gl1pg);
        goto out;
    }
rc = mod_l1_entry(pl1e, val, mfn_x(gl1mfn), MMU_NORMAL_PT_UPDATE, v, pg_owner);
page_unlock(gl1pg);
put_page(gl1pg);
out:
if (pl1e)
    unmap_domain_page(pl1e);
if (rc)
    return rc;

switch (flags & UVMF_FLUSHTYPE_MASK){
    case UVMF_TLB_FLUSH:
        switch ((bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK)){
            case UVMF_LOCAL:
                flush_tlb_local();
                break;
            case UVMF_ALL:
                mask = d->dirty_cpumask;
                break;
            default:
                mask = this_cpu(scratch_cpumask);
                rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void), mask);
                break;
        }
        if (mask)
            flush_tlb_mask(mask);

        break;
    case UVMF_INVLPG:
        switch ((bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK)){
            case UVMF_LOCAL:
                paging_invlpg(v, va);
                break;
            case UVMF_ALL:
                mask = d->dirty_cpumask;
                break;
            default:
                mask = this_cpu(scratch_cpumask);
                rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void), mask);
                break;
        }
        if (mask)
            flush_tlb_one_mask(mask, va);

        break;
    }
    return rc;
}
long do_update_va_mapping(unsigned long  va, u64 val64, unsigned long  flags)
{
    int rc = __do_update_va_mapping(va, val64, flags, current->domain);
    if (rc == -ERESTART)
        rc = hypercall_create_continuation(__HYPERVISOR_update_va_mapping, "lll", va, val64, flags);

    return rc;
}

long do_update_va_mapping_otherdomain(unsigned long  va, u64 val64, unsigned long  flags, domid_t domid)
{
    struct domain* pg_owner;
    int rc;
    if ((pg_owner = get_pg_owner(domid)) == NULL)
        return -ESRCH;

    rc = __do_update_va_mapping(va, val64, flags, pg_owner);
    put_pg_owner(pg_owner);
    if (rc == -ERESTART)
        rc = hypercall_create_continuation(__HYPERVISOR_update_va_mapping_otherdomain, "llli", va, val64, flags, domid);

    return rc;
}
int compat_update_va_mapping(unsigned int va, uint32_t lo, uint32_t hi, unsigned int flags)
{
    int rc = __do_update_va_mapping(va, ((uint64_t)(hi) << 32) | lo, flags, current->domain);
    if (rc == -ERESTART)
        rc = hypercall_create_continuation(__HYPERVISOR_update_va_mapping, "iiii", va, lo, hi, flags);

    return rc;
}
int compat_update_va_mapping_otherdomain(unsigned int va, uint32_t lo, uint32_t hi, unsigned int flags, domid_t domid)
{
    struct domain* pg_owner;
    int rc;
    if ((pg_owner = get_pg_owner(domid)) == NULL)
        return -ESRCH;

    rc = __do_update_va_mapping(va, ((uint64_t)(hi) << 32) | lo, flags, pg_owner);
    put_pg_owner(pg_owner);
    if (rc == -ERESTART)
        rc = hypercall_create_continuation(__HYPERVISOR_update_va_mapping_otherdomain, "iiiii", va, lo, hi, flags, domid);

    return rc;
}
typedef struct e820entry e820entry_t;
DEFINE_XEN_GUEST_HANDLE(e820entry_t);
struct  memory_map_context
{
    unsigned int n;
    unsigned long s;
    struct xen_memory_map map;
};

static int _handle_iomem_range(unsigned long  s, unsigned long  e, struct memory_map_context* ctxt)
{
    if (s > ctxt->s && !(s >> (paddr_bits - PAGE_SHIFT))){
        e820entry_t ent;
        XEN_GUEST_HANDLE_PARAM(e820entry_t) buffer_param;
        XEN_GUEST_HANDLE(e820entry_t) buffer;
        if (!guest_handle_is_null(ctxt->map.buffer)){
            if (ctxt->n + 1 >= ctxt->map.nr_entries)
                return -EINVAL;

            ent.addr = (uint64_t)(ctxt->s) << PAGE_SHIFT;
            ent.size = (uint64_t)(s - ctxt->s) << PAGE_SHIFT;
            ent.type = E820_RESERVED;
            buffer_param = guest_handle_cast(ctxt->map.buffer, e820entry_t);
            buffer = guest_handle_from_param(buffer_param, e820entry_t);
            if (__copy_to_guest_offset(buffer, ctxt->n, &ent, 1))
                return -EFAULT;
        }
        ctxt->n++;
    }
    ctxt->s = e + 1;
    return 0;
}
static int handle_iomem_range(unsigned long  s, unsigned long  e, void* p)
{
    int err = 0;
    do{
        unsigned long low = -1UL;
        unsigned int i;
        for (i = 0;i < nr_ioapics;++i){
            unsigned long mfn = paddr_to_pfn(mp_ioapics[i].mpc_apicaddr);
            if (mfn >= s && mfn <= e && mfn < low)
                low = mfn;
        }
        if (!(low + 1))
            break;

        if (s < low)
            err = _handle_iomem_range(s, low - 1, p);

        s = low + 1;
    } while (!err);
    return err || s > e ? err : _handle_iomem_range(s, e, p);
}

int xenmem_add_to_physmap_one(struct domain* d, unsigned int space, union xen_add_to_physmap_batch_extra extra, unsigned long  idx, gfn_t gpfn)
{
    struct page_info* page = NULL;
    unsigned long gfn = 0;
    unsigned long prev_mfn, old_gpfn;
    int rc = 0;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t p2mt;
    if (!paging_mode_translate(d))
        return -EACCES;

    switch (space){
        case XENMAPSPACE_shared_info:
            if (idx == 0)
                mfn = virt_to_mfn(d->shared_info);

            break;
        case XENMAPSPACE_grant_table:
            rc = gnttab_map_frame(d, idx, gpfn, &mfn);
            if (rc)
                return rc;

            break;
        case XENMAPSPACE_gmfn:
            {
                p2m_type_t p2mt;
                gfn = idx;
                mfn = get_gfn_unshare(d, gfn, &p2mt);
                if (p2m_is_shared(p2mt)){
                    put_gfn(d, gfn);
                    return -ENOMEM;
            }
            page = get_page_from_mfn(mfn, d);
            if (unlikely(!page))
                mfn = INVALID_MFN;

            break;
        }case XENMAPSPACE_gmfn_foreign:
        return p2m_add_foreign(d, idx, gfn_x(gpfn), extra.foreign_domid);
    default:
        break;
}
if (mfn_eq(mfn, INVALID_MFN)){
    rc = -EINVAL;
    goto put_both;
}
prev_mfn = mfn_x(get_gfn(d, gfn_x(gpfn), &p2mt));
if (mfn_valid(_mfn(prev_mfn))){
    if (is_xen_heap_mfn(prev_mfn))
         rc = guest_physmap_remove_page(d, gpfn, _mfn(prev_mfn), PAGE_ORDER_4K);
    else
        rc = guest_remove_page(d, gfn_x(gpfn));
}
put_gfn(d, gfn_x(gpfn));
if (rc)
    goto put_both;

old_gpfn = get_gpfn_from_mfn(mfn_x(mfn));
ASSERT(!SHARED_M2P(old_gpfn));
if (space == XENMAPSPACE_gmfn && old_gpfn != gfn){
    rc = -EXDEV;
    goto put_both;
}
if (old_gpfn != INVALID_M2P_ENTRY)
    rc = guest_physmap_remove_page(d, _gfn(old_gpfn), mfn, PAGE_ORDER_4K);

if (!rc)
    rc = guest_physmap_add_page(d, gpfn, mfn, PAGE_ORDER_4K);

put_both:
if (space == XENMAPSPACE_gmfn)
    put_gfn(d, gfn);
if (page)
    put_page(page);

return rc;
}

int arch_acquire_resource(struct domain* d, unsigned int type, unsigned int id, unsigned long  frame, unsigned int nr_frames, xen_pfn_t mfn_list[], unsigned int* flags)
{
int rc;
switch (type){
    case XENMEM_resource_ioreq_server:
        {
            ioservid_t ioservid = id;
            unsigned int i;
            rc = -EINVAL;
            if (!is_hvm_domain(d))
                break;

            if (id != (unsigned int)(ioservid))
                break;

            rc = 0;
            for (i = 0;i < nr_frames;i++){
                mfn_t mfn;
                rc = hvm_get_ioreq_server_frame(d, id, frame + i, &mfn);
                if (rc)
                    break;

                mfn_list[i] = mfn_x(mfn);
        }
        break;
    }
default:
    rc = -EOPNOTSUPP;
    break;
}
return rc;
}
long arch_memory_op(unsigned long  cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
int rc;
switch (cmd){
case XENMEM_set_memory_map:
    {
        struct xen_foreign_memory_map fmap;
        struct domain* d;
        struct e820entry* e820;
        if (copy_from_guest(&fmap, arg, 1))
            return -EFAULT;

        if (fmap.map.nr_entries > E820MAX)
            return -EINVAL;

        d = rcu_lock_domain_by_any_id(fmap.domid);
        if (d == NULL)
            return -ESRCH;

        rc = xsm_domain_memory_map(XSM_TARGET, d);
        if (rc){
            rcu_unlock_domain(d);
            return rc;
    }
    e820 = xmalloc_array(e820entry_t, fmap.map.nr_entries);
    if (e820 == NULL){
        rcu_unlock_domain(d);
        return -ENOMEM;
    }
    if (copy_from_guest(e820, fmap.map.buffer, fmap.map.nr_entries)){
        xfree(e820);
        rcu_unlock_domain(d);
        return -EFAULT;
    }
    spin_lock(&d->arch.e820_lock);
    xfree(d->arch.e820);
    d->arch.e820 = e820;
    d->arch.nr_e820 = fmap.map.nr_entries;
    spin_unlock(&d->arch.e820_lock);
    rcu_unlock_domain(d);
    return rc;
}
case XENMEM_memory_map:
    {
        struct xen_memory_map map;
        struct domain* d = current->domain;
        if (copy_from_guest(&map, arg, 1))
            return -EFAULT;

        spin_lock(&d->arch.e820_lock);
        if ((d->arch.nr_e820 == 0) || (d->arch.e820 == NULL)){
            spin_unlock(&d->arch.e820_lock);
            return -ENOSYS;
    }
    map.nr_entries = min(map.nr_entries, d->arch.nr_e820);
    if (copy_to_guest(map.buffer, d->arch.e820, map.nr_entries) || __copy_to_guest(arg, &map, 1)){
        spin_unlock(&d->arch.e820_lock);
        return -EFAULT;
    }
    spin_unlock(&d->arch.e820_lock);
    return 0;
}
case XENMEM_machine_memory_map:
    {
        struct memory_map_context ctxt;
        XEN_GUEST_HANDLE(e820entry_t) buffer;
        XEN_GUEST_HANDLE_PARAM(e820entry_t) buffer_param;
        unsigned int i;
        bool store;
        rc = xsm_machine_memory_map(XSM_PRIV);
        if (rc)
            return rc;

        if (copy_from_guest(&ctxt.map, arg, 1))
            return -EFAULT;

        store = !guest_handle_is_null(ctxt.map.buffer);
        if (store && ctxt.map.nr_entries < e820.nr_map + 1)
            return -EINVAL;

        buffer_param = guest_handle_cast(ctxt.map.buffer, e820entry_t);
        buffer = guest_handle_from_param(buffer_param, e820entry_t);
        if (store && !guest_handle_okay(buffer, ctxt.map.nr_entries))
            return -EFAULT;

        for (i = 0, ctxt.n = 0, ctxt.s = 0;i < e820.nr_map;++i, ++ctxt.n){
            unsigned long s = PFN_DOWN(e820.map[i].addr);
            if (s > ctxt.s){
                rc = rangeset_report_ranges(current->domain->iomem_caps, ctxt.s, s - 1, handle_iomem_range, &ctxt);
                if (!rc)
                    rc = handle_iomem_range(s, s, &ctxt);

                if (rc)
                    return rc;
        }
        if (store){
            if (ctxt.map.nr_entries <= ctxt.n + (e820.nr_map - i))
                return -EINVAL;

            if (__copy_to_guest_offset(buffer, ctxt.n, e820.map + i, 1))
                return -EFAULT;
        }
        ctxt.s = PFN_UP(e820.map[i].addr + e820.map[i].size);
    }
    if (ctxt.s){
        rc = rangeset_report_ranges(current->domain->iomem_caps, ctxt.s, ~0UL, handle_iomem_range, &ctxt);
        if (!rc && ctxt.s)
            rc = handle_iomem_range(~0UL, ~0UL, &ctxt);

        if (rc)
            return rc;
    }
    ctxt.map.nr_entries = ctxt.n;
    if (__copy_to_guest(arg, &ctxt.map, 1))
        return -EFAULT;

    return 0;
}
case XENMEM_machphys_mapping:
    {
        struct xen_machphys_mapping mapping = {.v_start = MACH2PHYS_VIRT_START, .v_end = MACH2PHYS_VIRT_END, .max_mfn = MACH2PHYS_NR_ENTRIES - 1};
        if (!mem_hotplug && is_hardware_domain(current->domain))
            mapping.max_mfn = max_page - 1;

        if (copy_to_guest(arg, &mapping, 1))
            return -EFAULT;

        return 0;
}case XENMEM_set_pod_target:
case XENMEM_get_pod_target:
    {
        xen_pod_target_t target;
        struct domain* d;
        struct p2m_domain* p2m;
        if (copy_from_guest(&target, arg, 1))
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(target.domid);
        if (d == NULL)
            return -ESRCH;

        if (cmd == XENMEM_set_pod_target)
            rc = xsm_set_pod_target(XSM_PRIV, d);
        else
            rc = xsm_get_pod_target(XSM_PRIV, d);

        if (rc != 0)
            goto pod_target_out_unlock;

        if (cmd == XENMEM_set_pod_target){
            if (target.target_pages > d->max_pages){
                rc = -EINVAL;
                goto pod_target_out_unlock;
        }
        rc = 0;
    }
    if (rc == -ERESTART){
        rc = hypercall_create_continuation(__HYPERVISOR_memory_op, "lh", cmd, arg);
    }else
        if (rc >= 0){
            p2m = p2m_get_hostp2m(d);
            target.tot_pages = d->tot_pages;
            target.pod_cache_pages = 0;
            target.pod_entries = 0;
            if (__copy_to_guest(arg, &target, 1)){
                rc = -EFAULT;
                goto pod_target_out_unlock;
            }
        }

    pod_target_out_unlock:
    rcu_unlock_domain(d);
    return rc;
}default:
    return subarch_memory_op(cmd, arg);
}
return 0;
}

int mmio_ro_emulated_write(enum x86_segment seg, unsigned long  offset, void* p_data, unsigned int bytes, struct x86_emulate_ctxt* ctxt)
{
struct mmio_ro_emulate_ctxt* mmio_ro_ctxt = ctxt->data;
if (((bytes | offset) & (bytes - 1)) || !bytes || offset != mmio_ro_ctxt->cr2){
gdprintk(XENLOG_WARNING, "bad access (cr2=%lx, addr=%lx, bytes=%u)\n", mmio_ro_ctxt->cr2, offset, bytes);
return X86EMUL_UNHANDLEABLE;
}
return X86EMUL_OKAY;
}

int mmcfg_intercept_write(enum x86_segment seg, unsigned long  offset, void* p_data, unsigned int bytes, struct x86_emulate_ctxt* ctxt)
{
struct mmio_ro_emulate_ctxt* mmio_ctxt = ctxt->data;
if (((bytes | offset) & (bytes - 1)) || bytes > 4 || !bytes || offset != mmio_ctxt->cr2){
gdprintk(XENLOG_WARNING, "bad write (cr2=%lx, addr=%lx, bytes=%u)\n", mmio_ctxt->cr2, offset, bytes);
return X86EMUL_UNHANDLEABLE;
}
offset &= 0xfff;
if (pci_conf_write_intercept(mmio_ctxt->seg, mmio_ctxt->bdf, offset, bytes, p_data) >= 0)
pci_mmcfg_write(mmio_ctxt->seg, PCI_BUS(mmio_ctxt->bdf), PCI_DEVFN2(mmio_ctxt->bdf), offset, bytes, *(uint32_t*)(p_data));

return X86EMUL_OKAY;
}

void* alloc_xen_pagetable(void)
{
if (system_state != SYS_STATE_early_boot){
    void* ptr = alloc_xenheap_page();
    BUG_ON(!hardware_domain && !ptr);
    return ptr;
}
return mfn_to_virt(mfn_x(alloc_boot_pages(1, 1)));
}
void free_xen_pagetable(void* v)
{
if (system_state != SYS_STATE_early_boot)
    free_xenheap_page(v);
}

static DEFINE_SPINLOCK(map_pgdir_lock);

static  l3_pgentry_t* virt_to_xen_l3e(unsigned long  v)
{
l4_pgentry_t* pl4e;
pl4e = &idle_pg_table[l4_table_offset(v)];
if (!(l4e_get_flags(*pl4e) & _PAGE_PRESENT)){
    bool locking = system_state > SYS_STATE_boot;
    l3_pgentry_t* pl3e = alloc_xen_pagetable();
    if (!pl3e)
        return NULL;

    clear_page(pl3e);
    if (locking)
        spin_lock(&map_pgdir_lock);

    if (!(l4e_get_flags(*pl4e) & _PAGE_PRESENT)){
        l4_pgentry_t l4e = l4e_from_paddr(__pa(pl3e), __PAGE_HYPERVISOR);
        l4e_write(pl4e, l4e);
        efi_update_l4_pgtable(l4_table_offset(v), l4e);
        pl3e = NULL;
    }
    if (locking)
        spin_unlock(&map_pgdir_lock);

    if (pl3e)
        free_xen_pagetable(pl3e);
}
return l4e_to_l3e(*pl4e) + l3_table_offset(v);
}
static l2_pgentry_t* virt_to_xen_l2e(unsigned long  v)
{
l3_pgentry_t* pl3e;
pl3e = virt_to_xen_l3e(v);
if (!pl3e)
    return NULL;

if (!(l3e_get_flags(*pl3e) & _PAGE_PRESENT)){
    bool locking = system_state > SYS_STATE_boot;
    l2_pgentry_t* pl2e = alloc_xen_pagetable();
    if (!pl2e)
        return NULL;

    clear_page(pl2e);
    if (locking)
        spin_lock(&map_pgdir_lock);

    if (!(l3e_get_flags(*pl3e) & _PAGE_PRESENT)){
        l3e_write(pl3e, l3e_from_paddr(__pa(pl2e), __PAGE_HYPERVISOR));
        pl2e = NULL;
    }
    if (locking)
        spin_unlock(&map_pgdir_lock);

    if (pl2e)
        free_xen_pagetable(pl2e);
}
BUG_ON(l3e_get_flags(*pl3e) & _PAGE_PSE);
return l3e_to_l2e(*pl3e) + l2_table_offset(v);
}

l1_pgentry_t* virt_to_xen_l1e(unsigned long  v)
{
l2_pgentry_t* pl2e;
pl2e = virt_to_xen_l2e(v);
if (!pl2e)
    return NULL;

if (!(l2e_get_flags(*pl2e) & _PAGE_PRESENT)){
    bool locking = system_state > SYS_STATE_boot;
    l1_pgentry_t* pl1e = alloc_xen_pagetable();
    if (!pl1e)
        return NULL;

    clear_page(pl1e);
    if (locking)
        spin_lock(&map_pgdir_lock);

    if (!(l2e_get_flags(*pl2e) & _PAGE_PRESENT)){
        l2e_write(pl2e, l2e_from_paddr(__pa(pl1e), __PAGE_HYPERVISOR));
        pl1e = NULL;
    }
    if (locking)
        spin_unlock(&map_pgdir_lock);

    if (pl1e)
        free_xen_pagetable(pl1e);
}
BUG_ON(l2e_get_flags(*pl2e) & _PAGE_PSE);
return l2e_to_l1e(*pl2e) + l1_table_offset(v);
}

int map_pages_to_xen(unsigned long  virt, mfn_t mfn, unsigned long  nr_mfns, unsigned int flags)
{
bool locking = system_state > SYS_STATE_boot;
l2_pgentry_t *pl2e, ol2e;
l1_pgentry_t *pl1e, ol1e;
unsigned int i;
while (nr_mfns != 0){
    l3_pgentry_t ol3e, *pl3e = virt_to_xen_l3e(virt);
    if (!pl3e)
        return -ENOMEM;

    ol3e = *pl3e;
    if (cpu_has_page1gb && !(((virt >> PAGE_SHIFT) | mfn_x(mfn)) & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)) && nr_mfns >= (1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) && !(flags & (_PAGE_PAT | MAP_SMALL_PAGES))){
        l3e_write_atomic(pl3e, l3e_from_mfn(mfn, l1f_to_lNf(flags)));
        if ((l3e_get_flags(ol3e) & _PAGE_PRESENT)){
            unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(2 * PAGETABLE_ORDER);
            if (l3e_get_flags(ol3e) & _PAGE_PSE){
                flush_flags(lNf_to_l1f(l3e_get_flags(ol3e)));
                flush_area(virt, flush_flags);
            }else{
                pl2e = l3e_to_l2e(ol3e);
                for (i = 0;i < L2_PAGETABLE_ENTRIES;i++){
                    ol2e = pl2e[i];
                    if (!(l2e_get_flags(ol2e) & _PAGE_PRESENT))
                        continue;

                    if (l2e_get_flags(ol2e) & _PAGE_PSE)
                        flush_flags(lNf_to_l1f(l2e_get_flags(ol2e)));
                    else{
                        unsigned int j;
                        pl1e = l2e_to_l1e(ol2e);
                        for (j = 0;j < L1_PAGETABLE_ENTRIES;j++)
                            flush_flags(l1e_get_flags(pl1e[j]));
                    }
                }
                flush_area(virt, flush_flags);
                for (i = 0;i < L2_PAGETABLE_ENTRIES;i++){
                    ol2e = pl2e[i];
                    if ((l2e_get_flags(ol2e) & _PAGE_PRESENT) && !(l2e_get_flags(ol2e) & _PAGE_PSE))
                        free_xen_pagetable(l2e_to_l1e(ol2e));
                }
                free_xen_pagetable(pl2e);
            }
        }
        virt += 1UL << L3_PAGETABLE_SHIFT;
        if (!mfn_eq(mfn, INVALID_MFN))
            mfn = mfn_add(mfn, 1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT));

        nr_mfns -= 1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
        continue;
    }
    if ((l3e_get_flags(ol3e) & _PAGE_PRESENT) && (l3e_get_flags(ol3e) & _PAGE_PSE)){
        unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(2 * PAGETABLE_ORDER);
        if (((l3e_get_pfn(ol3e) & ~(L2_PAGETABLE_ENTRIES * L1_PAGETABLE_ENTRIES - 1)) + (l2_table_offset(virt) << PAGETABLE_ORDER) + l1_table_offset(virt) == mfn_x(mfn)) && ((lNf_to_l1f(l3e_get_flags(ol3e)) ^ flags) & ~(_PAGE_ACCESSED | _PAGE_DIRTY)) == 0){
            i = (1u << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - (mfn_x(mfn) & ((1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1));
            if (i > nr_mfns)
                i = nr_mfns;

            virt += i << PAGE_SHIFT;
            if (!mfn_eq(mfn, INVALID_MFN))
                mfn = mfn_add(mfn, i);

            nr_mfns -= i;
            continue;
        }
        pl2e = alloc_xen_pagetable();
        if (pl2e == NULL)
            return -ENOMEM;

        for (i = 0;i < L2_PAGETABLE_ENTRIES;i++)
            l2e_write(pl2e + i,
                          l2e_from_pfn(l3e_get_pfn(ol3e) +
                                       (i << PAGETABLE_ORDER),
                                       l3e_get_flags(ol3e)));
        if (l3e_get_flags(ol3e) & _PAGE_GLOBAL)
            flush_flags |= FLUSH_TLB_GLOBAL;

        if (locking)
            spin_lock(&map_pgdir_lock);

        if ((l3e_get_flags(*pl3e) & _PAGE_PRESENT) && (l3e_get_flags(*pl3e) & _PAGE_PSE)){
            l3e_write_atomic(pl3e, l3e_from_mfn(virt_to_mfn(pl2e),
                                                    __PAGE_HYPERVISOR));
            pl2e = NULL;
        }
        if (locking)
            spin_unlock(&map_pgdir_lock);

        flush_area(virt, flush_flags);
        if (pl2e)
            free_xen_pagetable(pl2e);
    }
    pl2e = virt_to_xen_l2e(virt);
    if (!pl2e)
        return -ENOMEM;

    if (((((virt >> PAGE_SHIFT) | mfn_x(mfn)) & ((1u << PAGETABLE_ORDER) - 1)) == 0) && (nr_mfns >= (1u << PAGETABLE_ORDER)) && !(flags & (_PAGE_PAT | MAP_SMALL_PAGES))){
        ol2e = *pl2e;
        l2e_write_atomic(pl2e, l2e_from_mfn(mfn, l1f_to_lNf(flags)));
        if ((l2e_get_flags(ol2e) & _PAGE_PRESENT)){
            unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(PAGETABLE_ORDER);
            if (l2e_get_flags(ol2e) & _PAGE_PSE){
                flush_flags(lNf_to_l1f(l2e_get_flags(ol2e)));
                flush_area(virt, flush_flags);
            }else{
                pl1e = l2e_to_l1e(ol2e);
                for (i = 0;i < L1_PAGETABLE_ENTRIES;i++)
                    flush_flags(l1e_get_flags(pl1e[i]));
                flush_area(virt, flush_flags);
                free_xen_pagetable(pl1e);
            }
        }
        virt += 1UL << L2_PAGETABLE_SHIFT;
        if (!mfn_eq(mfn, INVALID_MFN))
            mfn = mfn_add(mfn, 1UL << PAGETABLE_ORDER);

        nr_mfns -= 1UL << PAGETABLE_ORDER;
    }else{
        if (!(l2e_get_flags(*pl2e) & _PAGE_PRESENT)){
            pl1e = virt_to_xen_l1e(virt);
            if (pl1e == NULL)
                return -ENOMEM;
        }else
            if (l2e_get_flags(*pl2e) & _PAGE_PSE){
                unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(PAGETABLE_ORDER);
                if ((((l2e_get_pfn(*pl2e) & ~(L1_PAGETABLE_ENTRIES - 1)) + l1_table_offset(virt)) == mfn_x(mfn)) && (((lNf_to_l1f(l2e_get_flags(*pl2e)) ^ flags) & ~(_PAGE_ACCESSED | _PAGE_DIRTY)) == 0)){
                    i = (1u << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) - (mfn_x(mfn) & ((1u << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1));
                    if (i > nr_mfns)
                        i = nr_mfns;

                    virt += i << L1_PAGETABLE_SHIFT;
                    if (!mfn_eq(mfn, INVALID_MFN))
                        mfn = mfn_add(mfn, i);

                    nr_mfns -= i;
                    goto check_l3;
                }
                pl1e = alloc_xen_pagetable();
                if (pl1e == NULL)
                    return -ENOMEM;

                for (i = 0;i < L1_PAGETABLE_ENTRIES;i++)
                    l1e_write(&pl1e[i],
                              l1e_from_pfn(l2e_get_pfn(*pl2e) + i,
                                           lNf_to_l1f(l2e_get_flags(*pl2e))));
                if (l2e_get_flags(*pl2e) & _PAGE_GLOBAL)
                    flush_flags |= FLUSH_TLB_GLOBAL;

                if (locking)
                    spin_lock(&map_pgdir_lock);

                if ((l2e_get_flags(*pl2e) & _PAGE_PRESENT) && (l2e_get_flags(*pl2e) & _PAGE_PSE)){
                    l2e_write_atomic(pl2e, l2e_from_mfn(virt_to_mfn(pl1e),
                                                        __PAGE_HYPERVISOR));
                    pl1e = NULL;
                }
                if (locking)
                    spin_unlock(&map_pgdir_lock);

                flush_area(virt, flush_flags);
                if (pl1e)
                    free_xen_pagetable(pl1e);
            }

        pl1e  = l2e_to_l1e(*pl2e) + l1_table_offset(virt);
        ol1e = *pl1e;
        l1e_write_atomic(pl1e, l1e_from_mfn(mfn, flags));
        if ((l1e_get_flags(ol1e) & _PAGE_PRESENT)){
            unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(0);
            flush_flags(l1e_get_flags(ol1e));
            flush_area(virt, flush_flags);
        }
        virt += 1UL << L1_PAGETABLE_SHIFT;
        if (!mfn_eq(mfn, INVALID_MFN))
            mfn = mfn_add(mfn, 1UL);

        nr_mfns -= 1UL;
        if ((flags == PAGE_HYPERVISOR) && ((nr_mfns == 0) || ((((virt >> PAGE_SHIFT) | mfn_x(mfn)) & ((1u << PAGETABLE_ORDER) - 1)) == 0))){
            unsigned long base_mfn;
            if (locking)
                spin_lock(&map_pgdir_lock);

            ol2e = *pl2e;
            if (!(l2e_get_flags(ol2e) & _PAGE_PRESENT)){
                if (locking)
                    spin_unlock(&map_pgdir_lock);

                continue;
            }
            if (l2e_get_flags(ol2e) & _PAGE_PSE){
                if (locking)
                    spin_unlock(&map_pgdir_lock);

                goto check_l3;
            }
            pl1e = l2e_to_l1e(ol2e);
            base_mfn = l1e_get_pfn(*pl1e) & ~(L1_PAGETABLE_ENTRIES - 1);
            for (i = 0;i < L1_PAGETABLE_ENTRIES;i++, pl1e++)
                if ((l1e_get_pfn(*pl1e) != (base_mfn + i)) || (l1e_get_flags(*pl1e) != flags))
                    break;
            if (i == L1_PAGETABLE_ENTRIES){
                l2e_write_atomic(pl2e, l2e_from_pfn(base_mfn,
                                                        l1f_to_lNf(flags)));
                if (locking)
                    spin_unlock(&map_pgdir_lock);

                flush_area(virt - PAGE_SIZE,
                               FLUSH_TLB_GLOBAL |
                               FLUSH_ORDER(PAGETABLE_ORDER));
                free_xen_pagetable(l2e_to_l1e(ol2e));
            }else
                if (locking)
                    spin_unlock(&map_pgdir_lock);
        }
    }
    check_l3:
    if (cpu_has_page1gb && (flags == PAGE_HYPERVISOR) && ((nr_mfns == 0) || !(((virt >> PAGE_SHIFT) | mfn_x(mfn)) & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)))){
        unsigned long base_mfn;
        if (locking)
            spin_lock(&map_pgdir_lock);

        ol3e = *pl3e;
        if (!(l3e_get_flags(ol3e) & _PAGE_PRESENT) || (l3e_get_flags(ol3e) & _PAGE_PSE)){
            if (locking)
                spin_unlock(&map_pgdir_lock);

            continue;
        }
        pl2e = l3e_to_l2e(ol3e);
        base_mfn = l2e_get_pfn(*pl2e) & ~(L2_PAGETABLE_ENTRIES * L1_PAGETABLE_ENTRIES - 1);
        for (i = 0;i < L2_PAGETABLE_ENTRIES;i++, pl2e++)
            if ((l2e_get_pfn(*pl2e) != (base_mfn + (i << PAGETABLE_ORDER))) || (l2e_get_flags(*pl2e) != l1f_to_lNf(flags)))
                break;
        if (i == L2_PAGETABLE_ENTRIES){
            l3e_write_atomic(pl3e, l3e_from_pfn(base_mfn,
                                                    l1f_to_lNf(flags)));
            if (locking)
                spin_unlock(&map_pgdir_lock);

            flush_area(virt - PAGE_SIZE,
                           FLUSH_TLB_GLOBAL |
                           FLUSH_ORDER(2*PAGETABLE_ORDER));
            free_xen_pagetable(l3e_to_l2e(ol3e));
        }else
            if (locking)
                spin_unlock(&map_pgdir_lock);
    }
}
return 0;
}

int populate_pt_range(unsigned long  virt, unsigned long  nr_mfns)
{
return map_pages_to_xen(virt, INVALID_MFN, nr_mfns, MAP_SMALL_PAGES);
}

int modify_xen_mappings(unsigned long  s, unsigned long  e, unsigned int nf)
{
bool locking = system_state > SYS_STATE_boot;
l2_pgentry_t* pl2e;
l1_pgentry_t* pl1e;
unsigned int i;
unsigned long v = s;
nf &= FLAGS_MASK;
ASSERT(IS_ALIGNED(s, PAGE_SIZE));
ASSERT(IS_ALIGNED(e, PAGE_SIZE));
while (v < e){
    l3_pgentry_t* pl3e = virt_to_xen_l3e(v);
    if (!pl3e || !(l3e_get_flags(*pl3e) & _PAGE_PRESENT)){
        ASSERT(!(nf & _PAGE_PRESENT));
        v += 1UL << L3_PAGETABLE_SHIFT;
        v &= ~((1UL << L3_PAGETABLE_SHIFT) - 1);
        continue;
    }
    if (l3e_get_flags(*pl3e) & _PAGE_PSE){
        if (l2_table_offset(v) == 0 && l1_table_offset(v) == 0 && ((e - v) >= (1UL << L3_PAGETABLE_SHIFT))){
            l3_pgentry_t nl3e = !(nf & _PAGE_PRESENT) ? l3e_empty() : l3e_from_pfn(l3e_get_pfn(*pl3e),
                                   (l3e_get_flags(*pl3e) & ~FLAGS_MASK) | nf);
            l3e_write_atomic(pl3e, nl3e);
            v += 1UL << L3_PAGETABLE_SHIFT;
            continue;
        }
        pl2e = alloc_xen_pagetable();
        if (!pl2e)
            return -ENOMEM;

        for (i = 0;i < L2_PAGETABLE_ENTRIES;i++)
            l2e_write(pl2e + i,
                          l2e_from_pfn(l3e_get_pfn(*pl3e) +
                                       (i << PAGETABLE_ORDER),
                                       l3e_get_flags(*pl3e)));
        if (locking)
            spin_lock(&map_pgdir_lock);

        if ((l3e_get_flags(*pl3e) & _PAGE_PRESENT) && (l3e_get_flags(*pl3e) & _PAGE_PSE)){
            l3e_write_atomic(pl3e, l3e_from_mfn(virt_to_mfn(pl2e),
                                                    __PAGE_HYPERVISOR));
            pl2e = NULL;
        }
        if (locking)
            spin_unlock(&map_pgdir_lock);

        if (pl2e)
            free_xen_pagetable(pl2e);
    }
    pl2e = l3e_to_l2e(*pl3e) + l2_table_offset(v);
    if (!(l2e_get_flags(*pl2e) & _PAGE_PRESENT)){
        ASSERT(!(nf & _PAGE_PRESENT));
        v += 1UL << L2_PAGETABLE_SHIFT;
        v &= ~((1UL << L2_PAGETABLE_SHIFT) - 1);
        continue;
    }
    if (l2e_get_flags(*pl2e) & _PAGE_PSE){
        if ((l1_table_offset(v) == 0) && ((e - v) >= (1UL << L2_PAGETABLE_SHIFT))){
            l2_pgentry_t nl2e = !(nf & _PAGE_PRESENT) ? l2e_empty() : l2e_from_pfn(l2e_get_pfn(*pl2e),
                                   (l2e_get_flags(*pl2e) & ~FLAGS_MASK) | nf);
            l2e_write_atomic(pl2e, nl2e);
            v += 1UL << L2_PAGETABLE_SHIFT;
        }else{
            pl1e = alloc_xen_pagetable();
            if (!pl1e)
                return -ENOMEM;

            for (i = 0;i < L1_PAGETABLE_ENTRIES;i++)
                l1e_write(&pl1e[i],
                              l1e_from_pfn(l2e_get_pfn(*pl2e) + i,
                                           l2e_get_flags(*pl2e) & ~_PAGE_PSE));
            if (locking)
                spin_lock(&map_pgdir_lock);

            if ((l2e_get_flags(*pl2e) & _PAGE_PRESENT) && (l2e_get_flags(*pl2e) & _PAGE_PSE)){
                l2e_write_atomic(pl2e, l2e_from_mfn(virt_to_mfn(pl1e),
                                                        __PAGE_HYPERVISOR));
                pl1e = NULL;
            }
            if (locking)
                spin_unlock(&map_pgdir_lock);

            if (pl1e)
                free_xen_pagetable(pl1e);
        }
    }else{
        l1_pgentry_t nl1e;
        pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(v);
        if (!(l1e_get_flags(*pl1e) & _PAGE_PRESENT))
            ASSERT(!(nf & _PAGE_PRESENT));

        nl1e = !(nf & _PAGE_PRESENT) ? l1e_empty()
                : l1e_from_pfn(l1e_get_pfn(*pl1e),
                               (l1e_get_flags(*pl1e) & ~FLAGS_MASK) | nf);
        l1e_write_atomic(pl1e, nl1e);
        v += PAGE_SIZE;
        if ((nf & _PAGE_PRESENT) || ((v != e) && (l1_table_offset(v) != 0)))
            continue;

        if (locking)
            spin_lock(&map_pgdir_lock);

        if (!(l2e_get_flags(*pl2e) & _PAGE_PRESENT)){
            if (locking)
                spin_unlock(&map_pgdir_lock);

            goto check_l3;
        }
        if (l2e_get_flags(*pl2e) & _PAGE_PSE){
            if (locking)
                spin_unlock(&map_pgdir_lock);

            continue;
        }
        pl1e = l2e_to_l1e(*pl2e);
        for (i = 0;i < L1_PAGETABLE_ENTRIES;i++)
            if (l1e_get_intpte(pl1e[i]) != 0)
                break;
        if (i == L1_PAGETABLE_ENTRIES){
            l2e_write_atomic(pl2e, l2e_empty());
            if (locking)
                spin_unlock(&map_pgdir_lock);

            flush_area(NULL, FLUSH_TLB_GLOBAL);
            free_xen_pagetable(pl1e);
        }else
            if (locking)
                spin_unlock(&map_pgdir_lock);
    }
    check_l3:
    if ((nf & _PAGE_PRESENT) || ((v != e) && (l2_table_offset(v) + l1_table_offset(v) != 0)))
        continue;
    if (locking)
        spin_lock(&map_pgdir_lock);

    if (!(l3e_get_flags(*pl3e) & _PAGE_PRESENT) || (l3e_get_flags(*pl3e) & _PAGE_PSE)){
        if (locking)
            spin_unlock(&map_pgdir_lock);

        continue;
    }
    pl2e = l3e_to_l2e(*pl3e);
    for (i = 0;i < L2_PAGETABLE_ENTRIES;i++)
        if (l2e_get_intpte(pl2e[i]) != 0)
            break;
    if (i == L2_PAGETABLE_ENTRIES){
        l3e_write_atomic(pl3e, l3e_empty());
        if (locking)
            spin_unlock(&map_pgdir_lock);

        flush_area(NULL, FLUSH_TLB_GLOBAL);
        free_xen_pagetable(pl2e);
    }else
        if (locking)
            spin_unlock(&map_pgdir_lock);
}
flush_area(NULL, FLUSH_TLB_GLOBAL);
return 0;
}

int destroy_xen_mappings(unsigned long  s, unsigned long  e)
{
return modify_xen_mappings(s, e, _PAGE_NONE);
}

void __set_fixmap(enum fixed_addresses idx, unsigned long  mfn, unsigned long  flags)
{
BUG_ON(idx >= __end_of_fixed_addresses);
map_pages_to_xen(__fix_to_virt(idx), _mfn(mfn), 1, flags);
}

void* arch_vmap_virt_end(void)
{
return fix_to_virt(__end_of_fixed_addresses);
}

void* ioremap(paddr_t pa, size_t len)
{
mfn_t mfn = _mfn(PFN_DOWN(pa));
void* va;
WARN_ON(page_is_ram_type(mfn_x(mfn), RAM_TYPE_CONVENTIONAL));
if (!((pa + len - 1) >> 20))
    va = __va(pa);
else{
    unsigned int offs = pa & (PAGE_SIZE - 1);
    unsigned int nr = PFN_UP(offs + len);
    va = __vmap(&mfn, nr, 1, 1, PAGE_HYPERVISOR_UCMINUS, VMAP_DEFAULT) + offs;
}
return (void*)(va);
}

int create_perdomain_mapping(struct domain* d, unsigned long  va, unsigned int nr, l1_pgentry_t** pl1tab, struct page_info** ppg)
{
struct page_info* pg;
l3_pgentry_t* l3tab;
l2_pgentry_t* l2tab;
l1_pgentry_t* l1tab;
int rc = 0;
ASSERT(va >= PERDOMAIN_VIRT_START &&
           va < PERDOMAIN_VIRT_SLOT(PERDOMAIN_SLOTS));
if (!d->arch.perdomain_l3_pg){
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if (!pg)
        return -ENOMEM;

    l3tab = __map_domain_page(pg);
    clear_page(l3tab);
    d->arch.perdomain_l3_pg = pg;
    if (!nr){
        unmap_domain_page(l3tab);
        return 0;
    }
}else
    if (!nr)
        return 0;
    else
        l3tab = __map_domain_page(d->arch.perdomain_l3_pg);

ASSERT(!l3_table_offset(va ^ (va + nr * PAGE_SIZE - 1)));
if (!(l3e_get_flags(l3tab[l3_table_offset(va)]) & _PAGE_PRESENT)){
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if (!pg){
        unmap_domain_page(l3tab);
        return -ENOMEM;
    }
    l2tab = __map_domain_page(pg);
    clear_page(l2tab);
    l3tab[l3_table_offset(va)] = l3e_from_page(pg, __PAGE_HYPERVISOR_RW);
}else
    l2tab = map_l2t_from_l3e(l3tab[l3_table_offset(va)]);

unmap_domain_page(l3tab);
if (!pl1tab && !ppg){
    unmap_domain_page(l2tab);
    return 0;
}
for (l1tab = NULL;!rc && nr--;){
    l2_pgentry_t* pl2e = l2tab + l2_table_offset(va);
    if (!(l2e_get_flags(*pl2e) & _PAGE_PRESENT)){
        if (pl1tab && !IS_NIL(pl1tab)){
            l1tab = alloc_xenheap_pages(0, MEMF_node(domain_to_node(d)));
            if (!l1tab){
                rc = -ENOMEM;
                break;
            }
            ASSERT(!pl1tab[l2_table_offset(va)]);
            pl1tab[l2_table_offset(va)] = l1tab;
            pg = virt_to_page(l1tab);
        }else{
            pg = alloc_domheap_page(d, MEMF_no_owner);
            if (!pg){
                rc = -ENOMEM;
                break;
            }
            l1tab = __map_domain_page(pg);
        }
        clear_page(l1tab);
        *pl2e = l2e_from_page(pg, __PAGE_HYPERVISOR_RW);
    }else
        if (!l1tab)
            l1tab = map_l1t_from_l2e(*pl2e);

    if (ppg && !(l1e_get_flags(l1tab[l1_table_offset(va)]) & _PAGE_PRESENT)){
        pg = alloc_domheap_page(d, MEMF_no_owner);
        if (pg){
            clear_domain_page(page_to_mfn(pg));
            if (!IS_NIL(ppg))
                *ppg++ = pg;

            l1tab[l1_table_offset(va)] =
                    l1e_from_page(pg, __PAGE_HYPERVISOR_RW | _PAGE_AVAIL0);
            l2e_add_flags(*pl2e, _PAGE_AVAIL0);
        }else
            rc = -ENOMEM;
    }
    va += PAGE_SIZE;
    if (rc || !nr || !l1_table_offset(va)){
        unmap_domain_page(l1tab);
        l1tab = NULL;
    }
}
ASSERT(!l1tab);
unmap_domain_page(l2tab);
return rc;
}

void destroy_perdomain_mapping(struct domain* d, unsigned long  va, unsigned int nr)
{
const l3_pgentry_t *l3tab, *pl3e;
ASSERT(va >= PERDOMAIN_VIRT_START &&
           va < PERDOMAIN_VIRT_SLOT(PERDOMAIN_SLOTS));
ASSERT(!nr || !l3_table_offset(va ^ (va + nr * PAGE_SIZE - 1)));
if (!d->arch.perdomain_l3_pg)
    return;

l3tab = __map_domain_page(d->arch.perdomain_l3_pg);
pl3e = l3tab + l3_table_offset(va);
if (l3e_get_flags(*pl3e) & _PAGE_PRESENT){
    const l2_pgentry_t* l2tab = map_l2t_from_l3e(*pl3e);
    const l2_pgentry_t* pl2e = l2tab + l2_table_offset(va);
    unsigned int i = l1_table_offset(va);
    while (nr){
        if (l2e_get_flags(*pl2e) & _PAGE_PRESENT){
            l1_pgentry_t* l1tab = map_l1t_from_l2e(*pl2e);
            for (;nr && i < L1_PAGETABLE_ENTRIES;--nr, ++i){
                if ((l1e_get_flags(l1tab[i]) & (_PAGE_PRESENT | _PAGE_AVAIL0)) == (_PAGE_PRESENT | _PAGE_AVAIL0))
                    free_domheap_page(l1e_get_page(l1tab[i]));

                l1tab[i] = l1e_empty();
            }
            unmap_domain_page(l1tab);
        }else
            if (nr + i < L1_PAGETABLE_ENTRIES)
                break;
            else
                nr -= L1_PAGETABLE_ENTRIES - i;

        ++pl2e;
        i = 0;
    }
    unmap_domain_page(l2tab);
}
unmap_domain_page(l3tab);
}

void free_perdomain_mappings(struct domain* d)
{
l3_pgentry_t* l3tab;
unsigned int i;
if (!d->arch.perdomain_l3_pg)
    return;

l3tab = __map_domain_page(d->arch.perdomain_l3_pg);
for (i = 0;i < PERDOMAIN_SLOTS;++i)
    if (l3e_get_flags(l3tab[i]) & _PAGE_PRESENT){
        struct page_info* l2pg = l3e_get_page(l3tab[i]);
        l2_pgentry_t* l2tab = __map_domain_page(l2pg);
        unsigned int j;
        for (j = 0;j < L2_PAGETABLE_ENTRIES;++j)
            if (l2e_get_flags(l2tab[j]) & _PAGE_PRESENT){
                struct page_info* l1pg = l2e_get_page(l2tab[j]);
                if (l2e_get_flags(l2tab[j]) & _PAGE_AVAIL0){
                    l1_pgentry_t* l1tab = __map_domain_page(l1pg);
                    unsigned int k;
                    for (k = 0;k < L1_PAGETABLE_ENTRIES;++k)
                        if ((l1e_get_flags(l1tab[k]) & (_PAGE_PRESENT | _PAGE_AVAIL0)) == (_PAGE_PRESENT | _PAGE_AVAIL0))
                            free_domheap_page(l1e_get_page(l1tab[k]));
                    unmap_domain_page(l1tab);
                }
                if (is_xen_heap_page(l1pg))
                    free_xenheap_page(page_to_virt(l1pg));
                else
                    free_domheap_page(l1pg);
            }
        unmap_domain_page(l2tab);
        free_domheap_page(l2pg);
    }
unmap_domain_page(l3tab);
free_domheap_page(d->arch.perdomain_l3_pg);
d->arch.perdomain_l3_pg = NULL;
}

static void __memguard_change_range(void* p, unsigned long  l, int guard)
{
unsigned long _p = (unsigned long )(p);
unsigned long _l = (unsigned long )(l);
unsigned int flags = __PAGE_HYPERVISOR_RW | MAP_SMALL_PAGES;
ASSERT(IS_ALIGNED(_p, PAGE_SIZE));
ASSERT(IS_ALIGNED(_l, PAGE_SIZE));
if (guard)
    flags &= ~_PAGE_PRESENT;

map_pages_to_xen(_p, virt_to_mfn(p), PFN_DOWN(_l), flags);
}

void memguard_guard_range(void* p, unsigned long  l)
{
__memguard_change_range(p, l, 1);
}
void memguard_unguard_range(void* p, unsigned long  l)
{
__memguard_change_range(p, l, 0);
}

void memguard_guard_stack(void* p)
{
BUILD_BUG_ON((IST_MAX + 1) * PAGE_SIZE + PRIMARY_STACK_SIZE > STACK_SIZE);
memguard_guard_range(p + IST_MAX * PAGE_SIZE, STACK_SIZE - PRIMARY_STACK_SIZE - IST_MAX * PAGE_SIZE);
}

void memguard_unguard_stack(void* p)
{
memguard_unguard_range(p + IST_MAX * PAGE_SIZE, STACK_SIZE - PRIMARY_STACK_SIZE - IST_MAX * PAGE_SIZE);
}

bool memguard_is_stack_guard_page(unsigned long  addr)
{
addr &= STACK_SIZE - 1;
return addr >= IST_MAX * PAGE_SIZE &&
           addr < STACK_SIZE - PRIMARY_STACK_SIZE;
}

void arch_dump_shared_mem_info(void)
{
printk("Shared frames %u -- Saved frames %u\n", mem_sharing_get_nr_shared_mfns(), mem_sharing_get_nr_saved_mfns());
}

const struct platform_bad_page* get_platform_badpages(unsigned int* array_size)
{
u32 igd_id;
static const struct platform_bad_page snb_bad_pages[] = {{.mfn = 0x20050000 >> PAGE_SHIFT}, {.mfn = 0x20110000 >> PAGE_SHIFT}, {.mfn = 0x20130000 >> PAGE_SHIFT}, {.mfn = 0x20138000 >> PAGE_SHIFT}, {.mfn = 0x40004000 >> PAGE_SHIFT}};
static const struct platform_bad_page hle_bad_page = {.mfn = 0x40000000 >> PAGE_SHIFT, .order = 10};
switch (cpuid_eax(1) & 0x000f3ff0){
    case 0x000406e0:
    case 0x00050650:
    case 0x000506e0:
    case 0x000806e0:
    case 0x000906e0:
        *array_size = (cpuid_eax(0) >= 7 && !(cpuid_ecx(1) & cpufeat_mask(X86_FEATURE_HYPERVISOR)) && (cpuid_count_ebx(7, 0) & cpufeat_mask(X86_FEATURE_HLE)));
        return &hle_bad_page;
}
*array_size = ARRAY_SIZE(snb_bad_pages);
igd_id = pci_conf_read32(0, 0, 2, 0, 0);
if (IS_SNB_GFX(igd_id))
    return snb_bad_pages;

return NULL;
}

void paging_invlpg(struct vcpu* v, unsigned long  linear)
{
if (!is_canonical_address(linear))
    return;

if ( paging_mode_enabled(v->domain) &&
         !paging_get_hostmode(v)->invlpg(v, linear) )
        return;

if (is_pv_vcpu(v))
    flush_tlb_one_local(linear);
else
    hvm_invlpg(v, linear);
}
void write_32bit_pse_identmap(uint32_t* l2)
{
unsigned int i;
for (i = 0;i < PAGE_SIZE / sizeof (*l2);i++)
    l2[i] = ((i << 22) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
}
unsigned long get_upper_mfn_bound(void)
{
unsigned long max_mfn;
max_mfn = mem_hotplug ? PFN_DOWN(mem_hotplug) : max_page;
max_mfn = min(max_mfn, 1UL << 32);
return min(max_mfn, 1UL << (paddr_bits - PAGE_SHIFT)) - 1;
}

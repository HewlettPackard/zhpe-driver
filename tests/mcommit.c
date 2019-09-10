#include <cpuid.h>
#include <x86intrin.h>

#include <zhpe_uapi.h>

struct mcommit_info {
    size_t              l1sz;
    void                (*flush)(const void *addr, size_t len, bool fence);
    void                (*invalidate)(const void *addr, size_t len, bool fence);
    void                (*mcommit)(void);
};

static void x86_clflush_range(const void *addr, size_t len,  bool fence);

static void null_mcommit(void)
{
}

static void __mcommit(void)
{
    mcommit();
}

static struct mcommit_info mcommit_info = {
    .l1sz               = 64,
    .flush              = x86_clflush_range,
    .invalidate         = x86_clflush_range,
    .mcommit            = null_mcommit,
};

static inline void io_mb(void)
{
    _mm_mfence();
}

static inline void io_wmb(void)
{
    _mm_sfence();
}

#include <stdio.h>

static void x86_clflush_range(const void *addr, size_t len,  bool fence)
{
    const char          *p =
        (const char *)((uintptr_t)addr & ~mcommit_info.l1sz);
    const char          *e = (const char *)addr + len;

    if (fence)
        io_wmb();
    for (; p < e; p += mcommit_info.l1sz)
        _mm_clflush(p);
}

static void x86_clflushopt_range(const void *addr, size_t len, bool fence)
{
    const char          *p =
        (const char *)((uintptr_t)addr & ~mcommit_info.l1sz);
    const char          *e = (const char *)addr + len;

    fprintf(stderr, "%s,%u:a 0x%p len 0x%x f %u\n",
            __func__, __LINE__, addr, len, fence);
    if (fence)
        io_wmb();
    for (; p < e; p += mcommit_info.l1sz) {
        fprintf(stderr, "%s,%u:a 0x%p\n", __func__, __LINE__, addr);
        _mm_clflushopt((void *)p);
    }
}

static void x86_clwb_range(const void *addr, size_t len, bool fence)
{
    const char          *p =
        (const char *)((uintptr_t)addr & ~mcommit_info.l1sz);
    const char          *e = (const char *)addr + len;

    fprintf(stderr, "%s,%u:a 0x%p len 0x%x f %u\n",
            __func__, __LINE__, addr, len, fence);
    if (fence)
        io_wmb();
    for (; p < e; p += mcommit_info.l1sz) {
        fprintf(stderr, "%s,%u:a 0x%p\n", __func__, __LINE__, addr);
        _mm_clwb((void *)p);
    }
}

static void __attribute__((constructor)) lib_init(void)
{
    uint                eax;
    uint                ebx;
    uint                ecx;
    uint                edx;

    if (__get_cpuid(0x1, &eax, &ebx, &ecx, &edx))
        mcommit_info.l1sz = (ebx >> 8) * 8;
    if (__get_cpuid_count(0x7, 0x0, &eax, &ebx, &ecx, &edx)) {
        if (ebx & bit_CLFLUSHOPT)
            mcommit_info.flush = x86_clflushopt_range;
            mcommit_info.invalidate = x86_clflushopt_range;
        if (ebx & bit_CLWB)
            mcommit_info.flush = x86_clflush_range;
    }
    if (__get_cpuid(CPUID_8000_0008, &eax, &ebx, &ecx, &edx)) {
        if (ebx & CPUID_8000_0008_EBX_MCOMMIT)
            mcommit_info.mcommit = __mcommit;
    }
}

void flush(const void *addr, size_t  len, bool fence)
{
    mcommit_info.flush(addr, len, fence);
}

void invalidate(const void *addr, size_t  len, bool fence)
{
    mcommit_info.invalidate(addr, len, fence);
    /* Must stop load speculation. */
    io_mb();
}

void commit(const void *addr, size_t  len, bool fence)
{
    mcommit_info.flush(addr, len, fence);
    mcommit_info.mcommit();
}

#ifdef TEST
static uint64_t         buf[8];
int main(void)
{
    commit(buf, sizeof(buf), true);
    return  0;
}
#endif

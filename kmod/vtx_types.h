#ifndef VTX_TYPES_H
#define VTX_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/compiler.h>
#define VTX_HOST	__section(".kprobes.text") notrace noinline
#define VTX_HOSTI	static __always_inline
#define VTX_UNREACHABLE()	__builtin_unreachable()
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
#define VTX_HOST
#define VTX_HOSTI	static inline __attribute__((always_inline))
#define VTX_UNREACHABLE()	__builtin_unreachable()
#ifndef READ_ONCE
#define READ_ONCE(x)	(*(const volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	(*(volatile __typeof__(x) *)&(x) = (v))
#endif
#endif

#define VTX_PAGE_SHIFT		12
#define VTX_PAGE_SIZE		(1ULL << VTX_PAGE_SHIFT)
#define VTX_PAGE_MASK		(~(VTX_PAGE_SIZE - 1))
#define VTX_2M			(1ULL << 21)
#define VTX_1G			(1ULL << 30)
#define VTX_512G		(1ULL << 39)

#define VTX_E_OK		0
#define VTX_E_NOMEM		(-12)
#define VTX_E_INVAL		(-22)
#define VTX_E_PERM		(-1)
#define VTX_E_EXIST		(-17)
#define VTX_E_NOENT		(-2)
#define VTX_E_RANGE		(-34)
#define VTX_E_FAULT		(-14)
#define VTX_E_BUSY		(-16)
#define VTX_E_NOSPC		(-28)

struct vtx_range {
	u64 start;
	u64 end;
};

VTX_HOSTI int vtx_range_overlap(u64 a0, u64 a1, u64 b0, u64 b1)
{
	return a0 < b1 && b0 < a1;
}

VTX_HOSTI void *vtx_pa2va(u64 dmap, u64 pa)
{
	return (void *)(uintptr_t)(dmap + pa);
}

#endif

#ifndef CUTILE_NUMBER_H

    #include "cxx.h"

    #define cutile_s8_min ~0x7f
    #define cutile_s8_max 0x7f

    #define cutile_u8_min 0x00
    #define cutile_u8_max 0xff

    #define cutile_s16_min ~0x7fff
    #define cutile_s16_max 0x7fff

    #define cutile_u16_min 0x0000
    #define cutile_u16_max 0xffff

    #define cutile_s32_min ~0x7fffffff
    #define cutile_s32_max 0x7fffffff

    #define cutile_u32_min 0x00000000
    #define cutile_u32_max 0xffffffff

    #define cutile_s64_min ~0x7fffffffffffffff
    #define cutile_s64_max 0x7fffffffffffffff

    #define cutile_u64_min 0x0000000000000000
    #define cutile_u64_max 0xffffffffffffffff

    #define cutile_get_u8_digits_m(nb, out)              \
    {                                                    \
        if (nb < 10) out = 1;                            \
        else if (nb < 100) out = 2;                      \
        else out = 3;                                    \
    }

    #define cutile_get_s8_digits_m(n, out)                                  \
    {                                                                       \
        s8 __cu_nb = n;                                                     \
        if (__cu_nb < 0) __cu_nb = __cu_nb == s8_min ? s8_max : -(__cu_nb); \
        if (__cu_nb < 10) out = 1;                                          \
        else if (__cu_nb < 100) out = 2;                                    \
        else out = 3;                                                       \
    }                                                                       \
 
    #define cutile_get_u16_digits_m(nb, out)  \
    {                                         \
        if (nb < 10) out = 1;                 \
        else if (nb < 100) out = 2;           \
        else if (nb < 1000) out = 3;          \
        else if (nb < 10000) out = 4;         \
        else out = 5;                         \
    }                                         \

    #define cutile_get_s16_digits_m(n, out)                                     \
    {                                                                           \
        s16 __cu_nb = n;                                                        \
        if (__cu_nb < 0) __cu_nb = __cu_nb == s16_min ? s16_max : -(__cu_nb);   \
        if (__cu_nb < 10) out = 1;                                              \
        else if (__cu_nb < 100) out = 2;                                        \
        else if (__cu_nb < 1000) out = 3;                                       \
        else if (__cu_nb < 10000) out = 4;                                      \
        else out = 5;                                                           \
    }                                                                           \

    #define cutile_get_u32_digits_m(nb, out)  \
    {                                         \
        if (nb < 10) out = 1;                 \
        else if (nb < 100) out = 2;           \
        else if (nb < 1000) out = 3;          \
        else if (nb < 10000) out = 4;         \
        else if (nb < 100000) out = 5;        \
        else if (nb < 1000000) out = 6;       \
        else if (nb < 10000000) out = 7;      \
        else if (nb < 100000000) out = 8;     \
        else if (nb < 1000000000) out = 9;    \
        else out = 10;                        \
    }                                         \

    #define cutile_get_s32_digits_m(n, out)                                     \
    {                                                                           \
        s32 __cu_nb = n;                                                        \
        if (__cu_nb < 0) __cu_nb = __cu_nb == s32_min ? s32_max : -(__cu_nb);   \
        if (__cu_nb < 10) out = 1;                                              \
        else if (__cu_nb < 100) out = 2;                                        \
        else if (__cu_nb < 1000) out = 3;                                       \
        else if (__cu_nb < 10000) out = 4;                                      \
        else if (__cu_nb < 100000) out = 5;                                     \
        else if (__cu_nb < 1000000) out = 6;                                    \
        else if (__cu_nb < 10000000) out = 7;                                   \
        else if (__cu_nb < 100000000) out = 8;                                  \
        else if (__cu_nb < 1000000000) out = 9;                                 \
        else out = 10;                                                          \
    }                                                                           \

    #define cutile_get_u64_digits_m(nb, out)             \
    {                                                    \
        if (nb < 10) out = 1;                            \
        else if (nb < 100) out = 2;                      \
        else if (nb < 1000) out = 3;                     \
        else if (nb < 10000) out = 4;                    \
        else if (nb < 100000) out = 5;                   \
        else if (nb < 1000000) out = 6;                  \
        else if (nb < 10000000) out = 7;                 \
        else if (nb < 100000000) out = 8;                \
        else if (nb < 1000000000) out = 9;               \
        else if (nb < 10000000000) out = 10;             \
        else if (nb < 100000000000) out = 11;            \
        else if (nb < 1000000000000) out = 12;           \
        else if (nb < 10000000000000) out = 13;          \
        else if (nb < 100000000000000) out = 14;         \
        else if (nb < 1000000000000000) out = 15;        \
        else if (nb < 10000000000000000) out = 16;       \
        else if (nb < 100000000000000000) out = 17;      \
        else if (nb < 1000000000000000000) out = 18;     \
        else if (nb < 10000000000000000000ULL) out = 19; \
        else out = 20;                                   \
    }
 
    #define cutile_get_s64_digits_m(n, out)                                     \
    {                                                                           \
        s64 __cu_nb = n;                                                        \
        if (__cu_nb < 0) __cu_nb = __cu_nb == s64_min ? s64_max : -(__cu_nb);   \
        if (__cu_nb < 10) out = 1;                                              \
        else if (__cu_nb < 100) out = 2;                                        \
        else if (__cu_nb < 1000) out = 3;                                       \
        else if (__cu_nb < 10000) out = 4;                                      \
        else if (__cu_nb < 100000) out = 5;                                     \
        else if (__cu_nb < 1000000) out = 6;                                    \
        else if (__cu_nb < 10000000) out = 7;                                   \
        else if (__cu_nb < 100000000) out = 8;                                  \
        else if (__cu_nb < 1000000000) out = 9;                                 \
        else if (__cu_nb < 10000000000) out = 10;                               \
        else if (__cu_nb < 100000000000) out = 11;                              \
        else if (__cu_nb < 1000000000000) out = 12;                             \
        else if (__cu_nb < 10000000000000) out = 13;                            \
        else if (__cu_nb < 100000000000000) out = 14;                           \
        else if (__cu_nb < 1000000000000000) out = 15;                          \
        else if (__cu_nb < 10000000000000000) out = 16;                         \
        else if (__cu_nb < 100000000000000000) out = 17;                        \
        else if (__cu_nb < 1000000000000000000) out = 18;                       \
        else out = 19;                                                          \
    }                                                                           \

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES

        #define s8_min cutile_s8_min
        #define s8_max cutile_s8_max

        #define u8_min cutile_u8_min
        #define u8_max cutile_u8_max

        #define s16_min cutile_s16_min
        #define s16_max cutile_s16_max

        #define u16_min cutile_u16_min
        #define u16_max cutile_u16_max

        #define s32_min cutile_s32_min
        #define s32_max cutile_s32_max

        #define u32_min cutile_u32_min
        #define u32_max cutile_u32_max

        #define s64_min cutile_s64_min
        #define s64_max cutile_s64_max

        #define u64_min cutile_u64_min
        #define u64_max cutile_u64_max

        #define get_u8_digits_m(n, out)  cutile_get_u8_digits_m(n, out)
        #define get_s8_digits_m(n, out)  cutile_get_s8_digits_m(n, out)
        #define get_u16_digits_m(n, out) cutile_get_u16_digits_m(n, out)
        #define get_s16_digits_m(n, out) cutile_get_s16_digits_m(n, out)
        #define get_u32_digits_m(n, out) cutile_get_u32_digits_m(n, out)
        #define get_s32_digits_m(n, out) cutile_get_s32_digits_m(n, out)
        #define get_u64_digits_m(n, out) cutile_get_u64_digits_m(n, out)
        #define get_s64_digits_m(n, out) cutile_get_s64_digits_m(n, out)

    #endif

    #define CUTILE_NUMBER_H

#endif

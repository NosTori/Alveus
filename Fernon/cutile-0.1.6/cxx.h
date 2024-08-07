// This file is a collection of basic tools I expect from any modern programming language.
// I named it "cxx.h" because it tries to express my ideal (naive/immature?) C/C++ language.

// This is the API, implementation is below this never-entered #if.
// I separated them because implementation is not easy to read, and it is not likely to be improved in the future.
#if 0

    // Keyword used for variables and functions that must not be visible outside their own compilation unit.
    #define internal

    // Keyword used for function variables that need to keep their value persistent between calls.
    #define persist

    // Suggests to the compiler that a function could be inlined.
    // Since C++17: can also suggest that a variable could be inlined.
    // For GCC (only in C) the inlining is forced.
    #define maybe_inline

    // Cast keyword like C cast, I find it easier to read than the usual C cast syntax.
    #define cast(type, expression)

    // Defines a packed structure.
    #define packed_struct(declaration)

    // Adds defer keyword for C++.
    // Defers allows you to ensure that some instructions are executed when exiting a scope (e.g. functions, if, etc...).
    // This is an alternative to RAII but this time you do not need to make any class with destructors.
    #ifdef CUTILE_CPP
        #define defer(expression)
    #endif

    // Performs assertion at compilation-time. A false assertion means a compilation error.
    #define cutile_compile_time_assert(assertion)

    // Integer explicit sized types. Mostly because int_XX_t is too long for me to write.
    // The number represents the number of bits.
    typedef u8;
    typedef s8;
    typedef u16;
    typedef s16;
    typedef u32;
    typedef s32;
    typedef u64;
    typedef s64;

    // Floating-point explicit sized types. I do not like "float". And mostly for the same reason as above.
    // The number represents the number of bits.
    typedef f32;
    typedef f64;

    // Boolean explicit sized types... Why not ??
    // The number represents the number of bits.
    typedef b8;
    typedef b32;

    #define cutile_b8_true
    #define cutile_b8_false
    #define cutile_b32_true
    #define cutile_b32_false

    // nullptr for C.
    #ifdef CUTILE_C
        #define nullptr
    #endif

    // Returns the offset of a structure field.
    #define cutile_field_offset_m(struct, field)

    // Transforms given token into a cstring literal.
    #define cutile_cstr_m(x)

    // Gets the line where this macro is called as a cstring.
    #define cutile_current_line_cstr_m

    // Returns swapped bytes of the given parameter.
    maybe_inline u16 cutile_bswap_u16(u16 val);
    maybe_inline u32 cutile_bswap_u32(u32 val);
    maybe_inline u64 cutile_bswap_u64(u64 val);

    // Targeted Operating Systems:
    // 0 or 1 according to what operating system you are targeting.
    #define LINUX       0|1
    #define MAC_OS      0|1
    #define UNIX_LIKE   0|1
    #define WINDOWS     0|1

    // Compilers:
    // 0 or 1 according to which compiler you are using.
    #define CLANG       0|1
    #define GCC         0|1
    #define MSVC        0|1

    ///////////////////////////////////
    // Short names for this API.
    // Define CUTILE_API_NO_SHORT_NAMES to disable every short name.

    #define compile_time_assert(assertion)

    #define b8_true
    #define b8_false

    #define b32_true
    #define b32_false

    #define field_offset_m(struct, field)

    #define cstr_m(x)

    #define current_src_line_cstr_m

    // Short names for the bswap API. 
    // Define CUTILE_BSWAP_API_NO_SHORT_NAMES to only disable them.
    // Define CUTILE_BSWAP_API_SHORT_NAMES to force enable them no matter what.
    #define bswap_u16(nb)
    #define bswap_u32(nb)
    #define bswap_u64(nb)

#endif

#ifndef CUTILE_CXX_H

    #include "cutile.h"

    #define internal static
    #define persist static

    #if defined(__GNUC__)
        #define maybe_inline __attribute__((always_inline)) inline
    #else
        #define maybe_inline inline
    #endif

    #define cast(type, expression) ((type)(expression))

    // packed_struct:

    #if defined(__GNUC__)
        #define packed_struct(declaration) struct declaration __attribute__((__packed__))
    #elif defined(_MSC_VER)
        #define packed_struct(declaration) __pragma(pack(push, 1)) struct declaration __pragma(pack(pop))
    #endif

    // defer implem
    #ifdef CUTILE_CPP
        template <typename Func>
        struct __cutile_defer
        {
            Func f;
            maybe_inline ~__cutile_defer() { f(); }
        };

        template <typename Func>
        maybe_inline __cutile_defer<Func> __cutile_create_defer(Func f) { return __cutile_defer<Func>{f}; }

        #define defer(expression) auto __cutile_defer__##__LINE__ = __cutile_create_defer([&]() { expression; })
    #endif

    // cutile_compile_time_assert
    #ifdef CUTILE_CPP
        #define cutile_compile_time_assert(a) static_assert(a)
    #else // CUTILE_C
        #if __STDC_VERSION__ >= 202311L // C23
            #define cutile_compile_time_assert(a) static_assert(a)
        #elif __STDC_VERSION__ >= 201112L // C11
            #define cutile_compile_time_assert(a) _Static_assert(a)
        #endif // __STDC_VERSION__
    #endif // CUTILE_CPP

    // explicit sized numeric types:
    ///////////////////////////////////////////////////////
    typedef char            s8;
    typedef unsigned char   u8;

    typedef short           s16;
    typedef unsigned short  u16;

    ////////////// Clang | GCC //////////////
    #if defined(__clang__) || defined(__GNUC__)

        typedef __INT32_TYPE__          s32;
        typedef unsigned __INT32_TYPE__ u32;

        typedef __INT64_TYPE__          s64;
        typedef unsigned __INT64_TYPE__ u64;

    #endif // __clang__ || __GNUC__
    /////////////////////////////////////////

    /////// Microsoft Visual C ////////
    #ifdef _MSC_VER

        typedef __int32             s32;
        typedef unsigned __int32    u32;

        typedef __int64             s64;
        typedef unsigned __int64    u64;

    #endif // _MSC_VER
    ///////////////////////////////////

    typedef float   f32;
    typedef double  f64;

    typedef u8  b8;
    typedef u32 b32;

    #define cutile_b8_true  0x01
    #define cutile_b8_false 0x00

    #define cutile_b32_true  0x00000001
    #define cutile_b32_false 0x00000000

    #ifndef CUTILE_API_NO_SHORT_NAMES
        #define b8_true  cutile_b8_true
        #define b8_false cutile_b8_false

        #define b32_true  cutile_b32_true
        #define b32_false cutile_b32_false
    #endif
    ///////////////////////////////////////////////////////

    // nullptr
    #ifdef CUTILE_C
        #define nullptr 0
    #endif

    // field_offset
    // Gets the offset (in bytes) of a field inside a structure.
    #define cutile_field_offset_m(structure, field) ((u64)(&((structure*)0x0)->field))

    #define cutile_cstr_m(x)  cutile_cstr2_m(x)
    #define cutile_cstr2_m(x) #x

    #define cutile_current_line_cstr_m cutile_cstr_m(__LINE__)

    #ifndef CUTILE_API_NO_SHORT_NAMES
        #define field_offset_m(structure, field)    cutile_field_offset_m(structure, field)
        #define cstr_m(x)                           cutile_cstr_m(x)
        #define current_src_line_cstr_m             cutile_current_line_cstr_m
    #endif

    #if defined(__GNUC__)
        maybe_inline u16 cutile_bswap_u16(u16 val) { return __builtin_bswap16(val); }
        maybe_inline u32 cutile_bswap_u32(u32 val) { return __builtin_bswap32(val); }
        maybe_inline u64 cutile_bswap_u64(u64 val) { return __builtin_bswap64(val); }
    #else
        maybe_inline u16 cutile_bswap_u16(u16 val) { return (val << 8) | (val >> 8); }
        maybe_inline u32 cutile_bswap_u32(u32 val) { return (val << 24) | ((val << 8) & 0x00FF0000) |
                                                            ((val >> 8) & 0x0000FF00) | (val >> 24); }
        maybe_inline u64 cutile_bswap_u64(u64 val) { return ((u64)(cutile_bswap_u32((u32)(val & 0xFFFFFFFF))) << 32) |
                                                            cutile_bswap_u32((u32)(val >> 32)); }
    #endif

    #if (!defined(CUTILE_API_NO_SHORT_NAMES) && !defined(CUTILE_BSWAP_API_NO_SHORT_NAMES)) || defined(CUTILE_BSWAP_API_SHORT_NAMES)
        #define bswap_u16(nb) cutile_bswap_u16(nb)
        #define bswap_u32(nb) cutile_bswap_u32(nb)
        #define bswap_u64(nb) cutile_bswap_u64(nb)
    #endif

    #ifdef __linux__
        #undef  LINUX
        #define LINUX     1
        #undef  UNIX_LIKE
        #define UNIX_LIKE 1
    #endif

    #ifdef _WIN32
        #undef  WINDOWS
        #define WINDOWS 1
    #endif

    #ifdef __APPLE__
        #include <TargetConditionals.h>
    
        #if TARGET_OS_MAC
            #undef  MAC_OS
            #define MAC_OS    1
            #undef  UNIX_LIKE
            #define UNIX_LIKE 1
        #endif
    #endif

    #if defined(__GNUC__) && !defined(__clang__)
        #undef  GCC
        #define GCC 1
    #elif defined(__clang__)
        #undef  CLANG
        #define CLANG 1
    #elif defined(_MSC_VER)
        #undef  MSVC
        #define MSVC 1
    #endif

    #define CUTILE_CXX_H

#endif

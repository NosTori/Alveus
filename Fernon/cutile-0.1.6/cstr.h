#ifndef CUTILE_CSTR_H
    #include "memory.h"

    // cstr are strings that end with a '\0'.

    CUTILE_C_API char* cutile_create_cstr_from_cstr(const char*, cutile_allocator*);
    CUTILE_C_API char* cutile_create_cstr_from_sub_cstr(const char*, u32 pos, u32 count, cutile_allocator*);

    #ifdef CUTILE_CPP
        maybe_inline void cutile_create_cstr(const char* cstr, cutile_allocator* allocator) { cutile_create_cstr_from_cstr(cstr, allocator); }
        maybe_inline void cutile_create_cstr(const char* cstr, u32 pos, u32 count, cutile_allocator* allocator) { cutile_create_cstr_from_sub_cstr(cstr, pos, count, allocator); }
    #endif

    CUTILE_C_API u32 cutile_cstr_length(const char* cstr);
    CUTILE_C_API b8  cutile_cstr_equals(const char* lhs, const char* rhs);

    CUTILE_C_API char* cutile_concat_cstrs(const char* lhs, const char* rhs, cutile_allocator*);

    CUTILE_C_API char* cutile_u8_to_cstr(u8, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_s8_to_cstr(s8, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_u16_to_cstr(u16, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_s16_to_cstr(s16, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_u32_to_cstr(u32, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_s32_to_cstr(s32, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_u64_to_cstr(u64, cutile_allocator* allocator);
    CUTILE_C_API char* cutile_s64_to_cstr(s64, cutile_allocator* allocator);

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define create_cstr_from_cstr(cstr_ptr, allocator_ptr)  cutile_create_cstr_from_cstr(cstr_ptr, allocator_ptr)
        #define create_cstr_from_sub_cstr(cstr_ptr, pos, count) cutile_create_cstr_from_sub_cstr(cstr_ptr, pos, count)
        #ifdef CUTILE_CPP
            #define create_cstr(...)                            cutile_create_cstr(__VA_ARGS__)
        #endif

        #define cstr_length(cstr_ptr)   cutile_cstr_length(cstr_ptr)
        #define cstr_equals(lhs, rhs)   cutile_cstr_equals(lhs, rhs)

        #define concat_cstrs(lhs, rhs, allocator_ptr) cutile_concat_cstrs(lhs, rhs, allocator_ptr)

        #define u8_to_cstr(nb, allocator_ptr) cutile_u8_to_cstr(nb, allocator_ptr)
        #define s8_to_cstr(nb, allocator_ptr) cutile_s8_to_cstr(nb, allocator_ptr)
        #define u16_to_cstr(nb, allocator_ptr) cutile_u16_to_cstr(nb, allocator_ptr)
        #define s16_to_cstr(nb, allocator_ptr) cutile_s16_to_cstr(nb, allocator_ptr)
        #define u32_to_cstr(nb, allocator_ptr) cutile_u32_to_cstr(nb, allocator_ptr)
        #define s32_to_cstr(nb, allocator_ptr) cutile_s32_to_cstr(nb, allocator_ptr)
        #define u64_to_cstr(nb, allocator_ptr) cutile_u64_to_cstr(nb, allocator_ptr)
        #define s64_to_cstr(nb, allocator_ptr) cutile_s64_to_cstr(nb, allocator_ptr)
    #endif

    #ifdef CUTILE_IMPLEM

        #include "number.h"

        char* cutile_create_cstr_from_cstr(const char* cstr, cutile_allocator* allocator)
        {
            u32 cstr_len = cutile_cstr_length(cstr);
            return cutile_create_cstr_from_sub_cstr(cstr, 0, cstr_len, allocator);
        }
    
        char* cutile_create_cstr_from_sub_cstr(const char* cstr, u32 pos, u32 count, cutile_allocator* allocator)
        {
            char* res = (char*)cutile_allocate_m(allocator, count + 1);
            copy_memory_m(res, cstr + pos, count);
            res[count] = '\0';
            return res;
        }
    
        u32 cutile_cstr_length(const char* cstr)
        {
            u32 i = 0;
            while (*(cstr + i)) ++i;
            return i; 
        }
    
        b8 cutile_cstr_equals(const char* lhs, const char* rhs)
        {
            for (;;)
            {
                if (!(*lhs) && !(*rhs)) break;
                if (*lhs++ != *rhs++) return cutile_b8_false;
            }
            return cutile_b8_true;
        }
    
        char* cutile_concat_cstrs(const char* lhs, const char* rhs, cutile_allocator* allocator)
        {
            u32 l_length = cutile_cstr_length(lhs);
            u32 r_length = cutile_cstr_length(rhs);
            char* result = cast(char*, cutile_allocate_m(allocator, sizeof(char) * (l_length + r_length + 1)));
            copy_memory_m(result, lhs, l_length);
            copy_memory_m(result + l_length, rhs, r_length);
            result[l_length + r_length] = '\0';
            return result;
        }
    
        #define cutile_unsigned_nb_to_cstr_m(nb, digits, allocator)         \
        {                                                                   \
            char* out = cutile_allocate_many_T_m(allocator, char, digits+1);\
            out[digits] = '\0';                                             \
            for (u32 i = digits; i > 0; --i)                                \
            {                                                               \
                out[i - 1] = nb % 10 + '0';                                 \
                nb /= 10;                                                   \
            }                                                               \
            return out;                                                     \
        }                                                                   \
    
        #define cutile_signed_nb_to_cstr_m(nb, digits, allocator)           \
        {                                                                   \
            u32 neg;                                                        \
            s32 mul;                                                        \
            char* out;                                                      \
            if (nb < 0)                                                     \
            {                                                               \
                out = cutile_allocate_many_T_m(allocator, char, digits+2);  \
                out[0] = '-';                                               \
                out[digits+1] = '\0';                                       \
                neg = 1;                                                    \
                mul = -1;                                                   \
            }                                                               \
            else                                                            \
            {                                                               \
                out = cutile_allocate_many_T_m(allocator, char, digits+1);  \
                out[digits] = '\0';                                         \
                neg = 0;                                                    \
                mul = 1;                                                    \
            }                                                               \
            for (u32 i = digits; i > 0; --i)                                \
            {                                                               \
                out[i - 1 + neg] = ((nb % 10) * mul) + '0';                 \
                nb /= 10;                                                   \
            }                                                               \
            return out;                                                     \
        }
    
        char* cutile_u8_to_cstr(u8 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u8_digits_m(nb, digits); cutile_unsigned_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_s8_to_cstr(s8 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s8_digits_m(nb, digits); cutile_signed_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_u16_to_cstr(u16 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u16_digits_m(nb, digits); cutile_unsigned_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_s16_to_cstr(s16 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s16_digits_m(nb, digits); cutile_signed_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_u32_to_cstr(u32 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u32_digits_m(nb, digits); cutile_unsigned_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_s32_to_cstr(s32 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s32_digits_m(nb, digits); cutile_signed_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_u64_to_cstr(u64 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u64_digits_m(nb, digits); cutile_unsigned_nb_to_cstr_m(nb, digits, allocator); }
    
        char* cutile_s64_to_cstr(s64 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s64_digits_m(nb, digits); cutile_signed_nb_to_cstr_m(nb, digits, allocator); }
    #endif

    #define CUTILE_CSTR_H
#endif

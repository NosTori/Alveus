#ifndef CUTILE_STR_H
    #include "memory.h"

    // String can be used to store textual data that we often refer to as "characters" or "code points".
    typedef struct cutile_string
    {
        u8*               data;
        u32               count;
        u32               size;

        cutile_allocator* allocator;
    } cutile_string;

    // String Creation:
    CUTILE_C_API cutile_string cutile_create_empty_str(cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_create_sized_empty_str(u32 size, cutile_allocator*);
    CUTILE_C_API cutile_string cutile_create_str_from_cstr(const char* cstr, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_copy_str(const cutile_string* str, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_create_str_from_buf(const u8* buf, u32 buf_len, cutile_allocator* allocator);

    #ifdef CUTILE_CPP
        maybe_inline cutile_string cutile_create_str(cutile_allocator* allocator) { return cutile_create_empty_str(allocator); }
        maybe_inline cutile_string cutile_create_str(u32 size, cutile_allocator* allocator) { return cutile_create_sized_empty_str(size, allocator); }
        maybe_inline cutile_string cutile_create_str(const char* cstr, cutile_allocator* allocator) { return cutile_create_str_from_cstr(cstr, allocator); }
        maybe_inline cutile_string cutile_create_str(const cutile_string* str, cutile_allocator* allocator) { return cutile_copy_str(str, allocator); }
        maybe_inline cutile_string cutile_create_str(const u8* buf, u32 buf_len, cutile_allocator* allocator) { return cutile_create_str_from_buf(buf, buf_len, allocator); }
    #endif

    // String Destruction:
    CUTILE_C_API void cutile_destroy_str(cutile_string* str);

    // String Modification:
    // str_insert*: index must be in a valid range: [0, str->count[.
    CUTILE_C_API void cutile_str_push_back(cutile_string* str, u8 c);
    CUTILE_C_API void cutile_str_push_back_utf8_cp(cutile_string* str, u32 cp);
    CUTILE_C_API void cutile_str_insert(cutile_string* str, u32 index, u8 c);
    CUTILE_C_API void cutile_str_insert_utf8_cp(cutile_string* str, u32 index, u32 cp);
    CUTILE_C_API void cutile_str_push_back_str(cutile_string* str, const cutile_string* rhs);
    CUTILE_C_API void cutile_str_push_back_cstr(cutile_string* str, const char* rhs);
    CUTILE_C_API void cutile_str_push_back_buf(cutile_string* str, const u8* buf, u64 buf_size);
    CUTILE_C_API void cutile_str_pop_back(cutile_string* str);
    CUTILE_C_API void cutile_resize_str(cutile_string* str, u32 size);

    #ifdef CUTILE_CPP
        maybe_inline void cutile_str_push_back(cutile_string* str, const cutile_string* rhs) { cutile_str_push_back(str, rhs); }
        maybe_inline void cutile_str_push_back(cutile_string* str, const char* rhs) { cutile_str_push_back(str, rhs); }
        maybe_inline void cutile_str_push_back(cutile_string* str, const u8* buf, u64 buf_size) { cutile_str_push_back(str, buf, buf_size); }
    #endif

    // String Transformation:
    CUTILE_C_API void cutile_reverse_str(cutile_string* str);
    CUTILE_C_API void cutile_reverse_sub_str(cutile_string* str, u32 offset, u32 count);

    #ifdef CUTILE_CPP
        maybe_inline void cutile_reverse_str(cutile_string* str, u32 offset, u32 count) { cutile_reverse_sub_str(str, offset, count); }
    #endif

    // String Lookup:

    // str_utf8_count: This function works for valid UTF-8 strings; do not use this function if you are unsure about the UTF-8 compliance of your string. You can check the compliance by using str_utf8_is_valid_utf8.
    CUTILE_C_API u8  cutile_str_at(const cutile_string* str, u32 index);
    CUTILE_C_API b8  cutile_str_equals_cstr(const cutile_string* str, const char* cstr);
    CUTILE_C_API b8  cutile_str_equals_cstr2(cutile_string str, const char* cstr);
    CUTILE_C_API b8  cutile_str_begins_with(const cutile_string* str, const char* val);
    CUTILE_C_API b8  cutile_str_ends_with(const cutile_string* str, const char* val);
    CUTILE_C_API u32 cutile_str_utf8_count(const cutile_string* str);
    CUTILE_C_API b8  cutile_str_is_valid_utf8(const cutile_string* str);
    #ifdef CUTILE_CPP
        maybe_inline b8 cutile_str_equals(const cutile_string* str, const char* cstr) { return cutile_str_equals_cstr(str, cstr); }
        maybe_inline b8 cutile_str_equals(cutile_string str, const char* cstr) { return cutile_str_equals_cstr2(str, cstr); }
    #endif

    typedef struct
    {
        cutile_string* s;
        u32            index;
        b8             valid;
        s32            value;
    } cutile_string_utf8_iterator;

    /* Usage:
      for (cutile_string_utf8_iterator it = cutile_str_create_utf8_iterator(&s);
           it.valid;
           cutile_str_utf8_iterate(&it))
      {
          ...
      }
     */
    CUTILE_C_API cutile_string_utf8_iterator cutile_str_create_utf8_iterator(cutile_string*);
    CUTILE_C_API void                        cutile_str_utf8_iterate(cutile_string_utf8_iterator*);

    // Conversion to cstr:
    CUTILE_C_API char* cutile_create_cstr_from_str(const cutile_string*, cutile_allocator*);
    #ifdef CUTILE_CPP
        maybe_inline void cutile_create_cstr(const cutile_string* str, cutile_allocator* allocator) { cutile_create_cstr_from_str(str, allocator); }
    #endif

    typedef struct cutile_string_view
    {
        const u8* data;
        u64       count;
    } cutile_string_view;
    
    #define cutile_cstr_lit_to_view_m(str_array)                                        \
        (cutile_string_view{.data = str_array, .count = sizeof(str_array)/sizeof(s8)})  \

    #define cutile_str_to_view_m(str)                               \
        (cutile_string_view{.data = str.data, .count = str.count})  \
    
    // String-View Lookup:
    CUTILE_C_API b8 cutile_str_view_equals_cstr(cutile_string_view* lhs, const char* rhs);

    // Conversion functions between strings and numbers:

    CUTILE_C_API u8  cutile_sub_str_to_u8(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API s8  cutile_sub_str_to_s8(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API u16 cutile_sub_str_to_u16(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API s16 cutile_sub_str_to_s16(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API u32 cutile_sub_str_to_u32(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API s32 cutile_sub_str_to_s32(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API u64 cutile_sub_str_to_u64(const cutile_string* s, u32 offset, u32 count);
    CUTILE_C_API s64 cutile_sub_str_to_s64(const cutile_string* s, u32 offset, u32 count);

    CUTILE_C_API u8  cutile_str_to_u8(const cutile_string* s);
    CUTILE_C_API s8  cutile_str_to_s8(const cutile_string* s);
    CUTILE_C_API u16 cutile_str_to_u16(const cutile_string* s);
    CUTILE_C_API s16 cutile_str_to_s16(const cutile_string* s);
    CUTILE_C_API u32 cutile_str_to_u32(const cutile_string* s);
    CUTILE_C_API s32 cutile_str_to_s32(const cutile_string* s);
    CUTILE_C_API u64 cutile_str_to_u64(const cutile_string* s);
    CUTILE_C_API s64 cutile_str_to_s64(const cutile_string* s);

    CUTILE_C_API cutile_string cutile_u8_to_str(u8, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_s8_to_str(s8, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_u16_to_str(u16, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_s16_to_str(s16, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_u32_to_str(u32, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_s32_to_str(s32, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_u64_to_str(u64, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_s64_to_str(s64, cutile_allocator* allocator);

    CUTILE_C_API cutile_string cutile_f32_to_str(f32, cutile_allocator* allocator);
    CUTILE_C_API cutile_string cutile_f64_to_str(f64, cutile_allocator* allocator);

    // nb_into_str: Pushes the number at the end of the string.
    CUTILE_C_API void cutile_u8_into_str(u8, cutile_string* out);
    CUTILE_C_API void cutile_s8_into_str(s8, cutile_string* out);
    CUTILE_C_API void cutile_u16_into_str(u16, cutile_string* out);
    CUTILE_C_API void cutile_s16_into_str(s16, cutile_string* out);
    CUTILE_C_API void cutile_u32_into_str(u32, cutile_string* out);
    CUTILE_C_API void cutile_s32_into_str(s32, cutile_string* out);
    CUTILE_C_API void cutile_u64_into_str(u64, cutile_string* out);
    CUTILE_C_API void cutile_s64_into_str(s64, cutile_string* out);

    CUTILE_C_API void cutile_f32_into_str(f32, cutile_string* out);
    CUTILE_C_API void cutile_f64_into_str(f64, cutile_string* out);

    CUTILE_C_API void cutile_u8_into_sub_str(u8, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_s8_into_sub_str(s8, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_u16_into_sub_str(u16, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_s16_into_sub_str(s16, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_u32_into_sub_str(u32, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_s32_into_sub_str(s32, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_u64_into_sub_str(u64, cutile_string* out, u32 index);
    CUTILE_C_API void cutile_s64_into_sub_str(s64, cutile_string* out, u32 index);

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        typedef cutile_string string;

        #define create_empty_str(allocator_ptr)                  cutile_create_empty_str((cutile_allocator*)(allocator_ptr))
        #define create_sized_empty_str(size, allocator_ptr)      cutile_create_sized_empty_str(size, (cutile_allocator*)(allocator_ptr))
        #define create_str_from_cstr(cstr, allocator_ptr)        cutile_create_str_from_cstr(cstr, (cutile_allocator*)(allocator_ptr))
        #define copy_str(str, allocator_ptr)                     cutile_copy_str(str, allocator_ptr)
        #define create_str_from_buf(buf, buf_len, allocator_ptr) cutile_create_str_from_buf(buf, buf_len, allocator_ptr)

        #ifdef CUTILE_CPP
            #define create_str(...) cutile_create_str(__VA_ARGS__)
        #endif

        #define destroy_str(str) cutile_destroy_str(str)

        #ifdef CUTILE_CPP
            #define str_push_back(...)                cutile_str_push_back(__VA_ARGS__)
        #else
            #define str_push_back(str, c)             cutile_str_push_back(str, c)
        #endif
        #define str_push_back_utf8_cp(str, cp)        cutile_str_push_back_utf8_cp(str, cp)
        #define str_insert(str, index, c)             cutile_str_insert(str, index, c)
        #define str_insert_utf8_cp(str, index, cp)    cutile_str_insert_utf8_cp(str, index, cp)
        #define str_push_bask_str(str, rhs)           cutile_str_push_back_str(str, rhs)
        #define str_push_back_cstr(str, rhs)          cutile_str_push_back_cstr(str, rhs)
        #define str_push_back_buf(str, buf, buf_size) cutile_str_push_back_buf(str, buf, buf_size)
        #define str_pop_back(str)                     cutile_str_pop_back(str)
        #define resize_str(str, size)                 cutile_resize_str(str, size)

        #ifdef CUTILE_CPP
            #define reverse_str(...)                cutile_reverse_str(__VA_ARGS__)
        #else
            #define reverse_str(str)                cutile_resize_str(str)
        #endif
        #define reverse_sub_str(str, offset, count) cutile_reverse_sub_str(str, offset, count)

        #define str_at(str_ptr, index)                  cutile_str_at(str_ptr, index)
        #define str_equals_cstr(str_ptr, cstr)          cutile_str_equals_cstr(str_ptr, cstr)
        #define str_equals_cstr2(str, cstr)             cutile_str_equals_cstr2(str, cstr)
        #define str_begins_with(str_ptr, cstr_pattern)  cutile_str_begins_with(str_ptr, cstr_pattern)
        #define str_ends_with(str_ptr, cstr_pattern)    cutile_str_ends_with(str_ptr, cstr_pattern)
        #define str_utf8_count(str_ptr)                 cutile_str_utf8_count(str_ptr)
        #define str_is_valid_utf8(str_ptr)              cutile_str_is_valid_utf8(str_ptr)
        #ifdef CUTILE_CPP
            #define str_equals(...)                     cutile_str_equals(__VA_ARGS__)
        #endif

        typedef cutile_string_utf8_iterator string_utf8_iterator;
        #define str_create_utf8_iterator(str_ptr)   cutile_str_create_utf8_iterator(str_ptr)
        #define str_utf8_iterate(it_ptr)            cutile_str_utf8_iterate(it_ptr)

        #define create_cstr_from_str(str_ptr, allocator_ptr)    cutile_create_cstr_from_str(str_ptr, allocator_ptr)

        #define sub_str_to_u8(str_ptr, offset, count)  cutile_sub_str_to_u8(str_ptr, offset, count)
        #define sub_str_to_s8(str_ptr, offset, count)  cutile_sub_str_to_s8(str_ptr, offset, count)
        #define sub_str_to_u16(str_ptr, offset, count) cutile_sub_str_to_u16(str_ptr, offset, count)
        #define sub_str_to_s16(str_ptr, offset, count) cutile_sub_str_to_s16(str_ptr, offset, count)
        #define sub_str_to_u32(str_ptr, offset, count) cutile_sub_str_to_u32(str_ptr, offset, count)
        #define sub_str_to_s32(str_ptr, offset, count) cutile_sub_str_to_s32(str_ptr, offset, count)
        #define sub_str_to_u64(str_ptr, offset, count) cutile_sub_str_to_u64(str_ptr, offset, count)
        #define sub_str_to_s64(str_ptr, offset, count) cutile_sub_str_to_s64(str_ptr, offset, count)

        #define str_to_u8(str_ptr)  cutile_str_to_u8(str_ptr)
        #define str_to_s8(str_ptr)  cutile_str_to_s8(str_ptr)
        #define str_to_u16(str_ptr) cutile_str_to_u16(str_ptr)
        #define str_to_s16(str_ptr) cutile_str_to_s16(str_ptr)
        #define str_to_u32(str_ptr) cutile_str_to_u32(str_ptr)
        #define str_to_s32(str_ptr) cutile_str_to_s32(str_ptr)
        #define str_to_u64(str_ptr) cutile_str_to_u64(str_ptr)
        #define str_to_s64(str_ptr) cutile_str_to_s64(str_ptr)

        #define u8_to_str(nb, allocator_ptr)  cutile_u8_to_str(nb, allocator_ptr)
        #define s8_to_str(nb, allocator_ptr)  cutile_s8_to_str(nb, allocator_ptr)
        #define u16_to_str(nb, allocator_ptr) cutile_u16_to_str(nb, allocator_ptr)
        #define s16_to_str(nb, allocator_ptr) cutile_s16_to_str(nb, allocator_ptr)
        #define u32_to_str(nb, allocator_ptr) cutile_u32_to_str(nb, allocator_ptr)
        #define s32_to_str(nb, allocator_ptr) cutile_s32_to_str(nb, allocator_ptr)
        #define u64_to_str(nb, allocator_ptr) cutile_u64_to_str(nb, allocator_ptr)
        #define s64_to_str(nb, allocator_ptr) cutile_s64_to_str(nb, allocator_ptr)

        #define f32_to_str(nb, allocator_ptr) cutile_f32_to_str(nb, allocator_ptr)
        #define f64_to_str(nb, allocator_ptr) cutile_f64_to_str(nb, allocator_ptr)

        #define u8_into_str(nb, str_out_ptr) cutile_u8_into_str(nb, str_out_ptr)
        #define s8_into_str(nb, str_out_ptr) cutile_s8_into_str(nb, str_out_ptr)
        #define u16_into_str(nb, str_out_ptr) cutile_u16_into_str(nb, str_out_ptr)
        #define s16_into_str(nb, str_out_ptr) cutile_s16_into_str(nb, str_out_ptr)
        #define u32_into_str(nb, str_out_ptr) cutile_u32_into_str(nb, str_out_ptr)
        #define s32_into_str(nb, str_out_ptr) cutile_s32_into_str(nb, str_out_ptr)
        #define u64_into_str(nb, str_out_ptr) cutile_u64_into_str(nb, str_out_ptr)
        #define s64_into_str(nb, str_out_ptr) cutile_s64_into_str(nb, str_out_ptr)

        #define f32_into_str(nb, str_out_ptr) cutile_f32_into_str(nb, str_out_ptr)
        #define f64_into_str(nb, str_out_ptr) cutile_f64_into_str(nb, str_out_ptr)

        #define u8_into_sub_str(nb, str_out_ptr, index) cutile_u8_into_sub_str(nb, str_out_ptr, index)
        #define s8_into_sub_str(nb, str_out_ptr, index) cutile_s8_into_sub_str(nb, str_out_ptr, index)
        #define u16_into_sub_str(nb, str_out_ptr, index) cutile_u16_into_sub_str(nb, str_out_ptr, index)
        #define s16_into_sub_str(nb, str_out_ptr, index) cutile_s16_into_sub_str(nb, str_out_ptr, index)
        #define u32_into_sub_str(nb, str_out_ptr, index) cutile_u32_into_sub_str(nb, str_out_ptr, index)
        #define s32_into_sub_str(nb, str_out_ptr, index) cutile_s32_into_sub_str(nb, str_out_ptr, index)
        #define u64_into_sub_str(nb, str_out_ptr, index) cutile_u64_into_sub_str(nb, str_out_ptr, index)
        #define s64_into_sub_str(nb, str_out_ptr, index) cutile_s64_into_sub_str(nb, str_out_ptr, index)
    #endif

    #ifdef CUTILE_IMPLEM

        #define CUTILE_STR_INCREMENT_COUNT 5

        #include "number.h"

        cutile_string cutile_create_empty_str(cutile_allocator* allocator)
        {
            cutile_string s;
            allocator->allocate(allocator, sizeof(u8));
            s.data = (u8*)cutile_allocate_m(allocator, sizeof(u8) * CUTILE_STR_INCREMENT_COUNT);
            s.count = 0;
            s.size = CUTILE_STR_INCREMENT_COUNT;
            s.allocator = allocator;
            return s;
        }

        cutile_string cutile_create_sized_empty_str(u32 size, cutile_allocator* allocator)
        {
            cutile_string s;
            s.data = (u8*)cutile_allocate_m(allocator, sizeof(u8) * size);
            s.count = 0;
            s.size = sizeof(u8)*size;
            s.allocator = allocator;
            return s;
        }

        maybe_inline u32 __cutile_str_cstr_length(const char* cstr)
        {
            u32 i = 0;
            while (cstr[i])
            {
                ++i;
            }
            return i;
        }

        cutile_string cutile_create_str_from_cstr(const char* cstr, cutile_allocator* allocator)
        {
            u32 count = __cutile_str_cstr_length(cstr);
            cutile_string s;
            s.data = (u8*)cutile_allocate_m(allocator, sizeof(u8) * count);
            cutile_copy_memory_m((s8*)s.data, cstr, count);
            s.count = count;
            s.size = count;
            s.allocator = allocator;
            return s;
        }

        cutile_string cutile_copy_str(const cutile_string* original, cutile_allocator* allocator)
        {
            cutile_string s;
            s.data = (u8*)cutile_allocate_m(allocator, sizeof(u8) * original->count);
            cutile_copy_memory_m(s.data, original->data, original->count);
            s.count = original->count;
            s.size = original->size;
            s.allocator = allocator;
            return s;
        }
    
        cutile_string cutile_create_str_from_buf(const u8* buf, u32 buf_len, cutile_allocator* allocator)
        {
            cutile_string s;
            s.data = cutile_allocate_many_T_m(allocator, u8, buf_len);
            for (u32 i = 0; i < buf_len; ++i) s.data[i] = buf[i];
            s.count = buf_len;
            s.size = s.count;
            s.allocator = allocator;
            return s;
        }
    
        void cutile_destroy_str(cutile_string* str)
        {
            cutile_deallocate_m(str->allocator, str->data);
        }
    
        void cutile_resize_str(cutile_string* str, u32 size)
        {
            u8* new_data = (u8*)cutile_allocate_m(str->allocator, size);
            if (size < str->count)
            {
                for (u32 i = 0; i < size; ++i) new_data[i] = str->data[i];
                str->count = size;
            }
            else
            {
                for (u32 i = 0; i < str->count; ++i) new_data[i] = str->data[i];
            }
            cutile_deallocate_m(str->allocator, str->data);
            str->data = new_data;
            str->size = size;
        }
    
        void cutile_str_push_back(cutile_string* str, u8 c)
        {
            if (str->count + 1 >= str->size) cutile_resize_str(str, str->size + 1 + CUTILE_STR_INCREMENT_COUNT);
            str->data[str->count++] = c;
        }
    
        void cutile_str_push_back_utf8_cp(cutile_string* str, u32 c)
        {
            if (c <= 0x7F) // One byte long.
            {
                cutile_str_push_back(str, cast(u8, c));
            }
            else if (c <= 0xDF00) // Two bytes long.
            {
                if (str->count + 2 >= str->size) cutile_resize_str(str, str->size + 2 + CUTILE_STR_INCREMENT_COUNT);
                str->data[str->count++] = (c >> 8) & 0xFF;
                str->data[str->count++] = c & 0xFF;
            }
            else if (c <= 0xEF0000) // Three bytes long.
            {
                if (str->count + 3 >= str->size) cutile_resize_str(str, str->size + 3 + CUTILE_STR_INCREMENT_COUNT);
                str->data[str->count++] = (c >> 16) & 0xFF;
                str->data[str->count++] = (c >> 8) & 0xFF;
                str->data[str->count++] = c & 0xFF;
            }
            else // Four bytes long
            {
                if (str->count + 4 >= str->size) cutile_resize_str(str, str->size + 4 + CUTILE_STR_INCREMENT_COUNT);
                str->data[str->count++] = (c >> 24) & 0xFF;
                str->data[str->count++] = (c >> 16) & 0xFF;
                str->data[str->count++] = (c >> 8) & 0xFF;
                str->data[str->count++] = c & 0xFF;
            }
        }

        void cutile_str_insert(cutile_string* str, u32 index, u8 c)
        {
            if (str->count + 1 > str->size) cutile_resize_str(str, str->size + CUTILE_STR_INCREMENT_COUNT);
            for (u32 i = index; i < str->count; ++i)
            {
                u32 j = str->count - (i - index) - 1;
                str->data[j + 1] = str->data[j];
            }
            str->data[index] = c;
            str->count += 1;
        }
    
        void cutile_str_insert_utf8_cp(cutile_string* str, u32 index, u32 c)
        {
            u32 current_index = 0;
            u32 byte_index = 0;
            for (cutile_string_utf8_iterator it = cutile_str_create_utf8_iterator(str);
                 it.valid && current_index < index;
                 cutile_str_utf8_iterate(&it))
            {
                byte_index = it.index;
                ++current_index;
            }

            if (c <= 0x7F) // One byte long.
            {
                if (str->count + 1 >= str->size) cutile_resize_str(str, str->size + 1 + CUTILE_STR_INCREMENT_COUNT);
                for (u32 i = byte_index; i < str->count; ++i)
                {
                    u32 j = str->count - (i - byte_index) - 1;
                    str->data[j + 1] = str->data[j];
                }
                str->data[byte_index] = (u8)c;
                str->count++;
            }
            else if (c <= 0xDF00) // Two bytes long.
            {
                if (str->count + 2 >= str->size) cutile_resize_str(str, str->size + 2 + CUTILE_STR_INCREMENT_COUNT);
                for (u32 i = byte_index; i < str->count; ++i)
                {
                    u32 j = str->count - (i - byte_index) - 1;
                    str->data[j + 2] = str->data[j];
                }
                str->data[byte_index] = (c >> 8) & 0xFF;
                str->data[byte_index + 1] = c & 0xFF;
                str->count += 2;
            }
            else if (c <= 0xEF0000) // Three bytes long.
            {
                if (str->count + 3 >= str->size) cutile_resize_str(str, str->size + 3 + CUTILE_STR_INCREMENT_COUNT);
                for (u32 i = byte_index; i < str->count; ++i)
                {
                    u32 j = str->count - (i - byte_index) - 1;
                    str->data[j + 3] = str->data[j];
                }
                str->data[byte_index] = (c >> 16) & 0xFF;
                str->data[byte_index + 1] = (c >> 8) & 0xFF;
                str->data[byte_index + 2] = c & 0xFF;
                str->count += 3;
            }
            else // Four bytes long
            {
                if (str->count + 4 >= str->size) cutile_resize_str(str, str->size + 4 + CUTILE_STR_INCREMENT_COUNT);
                for (u32 i = byte_index; i < str->count; ++i)
                {
                    u32 j = str->count - (i - byte_index) - 1;
                    str->data[j + 4] = str->data[j];
                }
                str->data[byte_index] = (c >> 24) & 0xFF;
                str->data[byte_index + 1] = (c >> 16) & 0xFF;
                str->data[byte_index + 2] = (c >> 8) & 0xFF;
                str->data[byte_index + 3] = c & 0xFF;
                str->count += 4;
            }
        }
    
        void cutile_str_push_back_str(cutile_string* str, const cutile_string* rhs)
        {
            if (str->count + rhs->count >= str->size) cutile_resize_str(str, str->size + rhs->count);
            copy_memory_m(str->data + str->count, rhs->data, rhs->count);
            str->count += rhs->count;
        }
    
        void cutile_str_push_back_cstr(cutile_string* str, const char* rhs)
        {
            u32 rlen = __cutile_str_cstr_length(rhs);
            if (str->count + rlen >= str->size) resize_str(str, str->size + rlen);
            copy_memory_m(str->data + str->count, (u8*)rhs, rlen);
            str->count += rlen;
        }
    
        void cutile_str_push_back_buf(cutile_string* str, const u8* buf, u64 buf_size)
        {
            if (str->count + buf_size >= str->size) cutile_resize_str(str, str->size + buf_size);
            copy_memory_m(str->data + str->count, buf, buf_size);
            str->count += buf_size;
        }
    
        void cutile_str_pop_back(cutile_string* str)
        {
            str->count--;
        }
    
        void cutile_reverse_str(cutile_string* str)
        {
            u32 end = str->count * 0.5;
            u32 j = str->count - 1;
            for (u32 i = 0; i < end; ++i, --j)
            {
                u8 dump = str->data[i];
                str->data[i] = str->data[j];
                str->data[j] = dump;
            }
        }
    
        void cutile_reverse_sub_str(cutile_string* str, u32 offset, u32 count)
        {
            u32 mid = offset + (count * 0.5);
            u32 j = offset + count - 1;
            for (u32 i = offset; i < mid; ++i, --j)
            {
                u8 dump = str->data[i];
                str->data[i] = str->data[j];
                str->data[j] = dump;
            }
        }
    
        u8 cutile_str_at(const cutile_string* str, u32 index)
        {
            return str->data[index];
        }
      
        b8 cutile_str_equals_cstr(const cutile_string* str, const char* cstr)
        {
            u32 clen = __cutile_str_cstr_length(cstr);
            if (clen != str->count) return cutile_b8_false;
            b8 result;
            memory_equals_m(str->data, (u8*)cstr, clen, result);
            return result;
        }
    
        b8 cutile_str_equals_cstr2(cutile_string str, const char* cstr)
        {
            return cutile_str_equals_cstr(&str, cstr);
        }
    
        b8 cutile_str_begins_with(const cutile_string* str, const char* val)
        {
            u32 count = __cutile_str_cstr_length(val);
            if (count > str->count) return cutile_b8_false;
            b8 result;
            cutile_memory_equals_m(str->data, (u8*)val, count, result);
            return result;
        }

        b8 cutile_str_ends_with(const cutile_string* str, const char* val)
        {
            u32 count = __cutile_str_cstr_length(val);
            if (count > str->count) return cutile_b8_false;
            b8 result;
            cutile_memory_equals_m(str->data + str->count - count, (u8*)val, count, result);
            return result;
        }
    
        /* Here are some rules from the RFC regarding bytes sequences in an UTF-8 string:
        
        https://www.rfc-editor.org/rfc/rfc3629#section-4
        
        Copyright Notice
        
           Copyright (C) The Internet Society (2003).  All Rights Reserved.
        
        4.  Syntax of UTF-8 Byte Sequences
        
           For the convenience of implementors using ABNF, a definition of UTF-8
           in ABNF syntax is given here.
        
           A UTF-8 string is a sequence of octets representing a sequence of UCS
           characters.  An octet sequence is valid UTF-8 only if it matches the
           following syntax, which is derived from the rules for encoding UTF-8
           and is expressed in the ABNF of [RFC2234].
        
           UTF8-octets = *( UTF8-char )
           UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
           UTF8-1      = %x00-7F
           UTF8-2      = %xC2-DF UTF8-tail
        
           UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
                         %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
           UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
                         %xF4 %x80-8F 2( UTF8-tail )
           UTF8-tail   = %x80-BF
        */
    
    
        u32 cutile_str_utf8_count(const cutile_string* str)
        {
            // This function does not check for any UTF-8 corruption into the given string, obviously for speed reasons !!!
    
            u32 count = 0;
            for (u32 i = 0; i < str->count;)
            {
                if (str->data[i] <= 0x7F) i += 1;
                else if (str->data[i] <= 0xDF) i += 2;
                else if (str->data[i] <= 0xEF) i += 3;
                else i += 4;
                ++count;
            }
            return count;
        }
    
        b8 cutile_str_is_valid_utf8(const cutile_string* str)
        {
            for (u32 i = 0; i < str->count; ++i)
            {
                if (str->data[i] <= 0x7F) continue;
    
                else if (str->data[i] >= 0xC2 && str->data[i] <= 0xDF) // UTF8-2 (2 bytes)
                {
                    ++i;
                    if (i >= str->count) return cutile_b8_false;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] == 0xE0) // UTF8-3 (3 bytes)
                {
                    if (i + 2 >= str->count) return b8_false;
                    ++i;
                    if (str->data[i] < 0xA0 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] >= 0xE1 && str->data[i] <= 0xEC) // UTF8-3 (3 bytes)
                {
                    if (i + 2 >= str->count) return b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] == 0xED) // UTF8-3 (3 bytes)
                {
                    if (i + 2 >= str->count) return b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0x9F) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] >= 0xEE && str->data[i] <= 0xEF) // UTF8-3 (3 bytes)
                {
                    if (i + 2 >= str->count) return b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] == 0xF0) // UTF8-4 (4 bytes)
                {
                    if (i + 3 >= str->count) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x90 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] >= 0xF1 && str->data[i] <= 0xF3) // UTF8-3 (3 bytes)
                {
                    if (i + 3 >= str->count) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
    
                else if (str->data[i] == 0xF4) // UTF8-4 (4 bytes)
                {
                    if (i + 3 >= str->count) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0x8F) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    ++i;
                    if (str->data[i] < 0x80 || str->data[i] > 0xBF) return cutile_b8_false;
                    continue;
                }
            }
            return cutile_b8_true;
        }
    

        cutile_string_utf8_iterator cutile_str_create_utf8_iterator(cutile_string* s)
        {
            cutile_string_utf8_iterator it = {.s = s, .index = 0, .valid = b8_false};

            if (0 < s->count)
            {
                it.valid = b8_true;
                if (s->data[0] <= 0x7F) // One byte long.
                {
                    it.value = s->data[0];
                    it.index++;
                }
                else if (s->data[0] <= 0xDF) // Two bytes long.
                {
                    it.value = cast(s32, s->data[0]) << 8 | s->data[1];
                    it.index += 2;
                }
                else if (s->data[0] <= 0xEF) // Three bytes long.
                {
                    it.value = (cast(s32, s->data[0]) << 16) | 
                               (cast(s32, s->data[1]) << 8) | 
                               s->data[2];
                    it.index += 3;
                }
                else // Four bytes long.
                {
                    it.value = (cast(s32, s->data[0]) << 24) | 
                               (cast(s32, s->data[1]) << 16) | 
                               (cast(s32, s->data[2]) << 8) |
                               s->data[3];
                    it.index += 4;
                }
            }

            return it;
        }

        void cutile_str_utf8_iterate(cutile_string_utf8_iterator* it)
        {
            if (it->index >= it->s->count) {
                it->valid = b8_false;
                return;
            }

            if (it->s->data[it->index] <= 0x7F) // One byte long.
            {
                it->value = it->s->data[it->index];
                it->index++;
            }
            else if (it->s->data[0] <= 0xDF) // Two bytes long.
            {
                it->value = it->s->data[it->index + 1] | 
                            (cast(s32, it->s->data[it->index]) << 8);
                it->index += 2;
            }
            else if (it->s->data[it->index] <= 0xEF) // Three bytes long.
            {
                it->value = it->s->data[it->index + 2] | 
                            (cast(s32, it->s->data[it->index + 1]) << 8) | 
                            (cast(s32, it->s->data[it->index]) << 16);
                it->index += 3;
            }
            else // Four bytes long.
            {
                it->value = it->s->data[it->index + 3] | 
                            (cast(s32, it->s->data[it->index + 2]) << 8) | 
                            (cast(s32, it->s->data[it->index + 1]) << 16) | 
                            (it->s->data[it->index] << 24);
                it->index += 4;
            }
        }

        char* cutile_create_cstr_from_str(const cutile_string* str, cutile_allocator* allocator)
        {
            char* res = (char*)cutile_allocate_m(allocator, str->count + 1);
            copy_memory_m(res, (char*)str->data, str->count);
            res[str->count] = '\0';
            return res;
        }

        b8 cutile_str_view_equals_cstr(cutile_string_view* lhs, const char* rhs)
        {
            u32 rhs_length = __cutile_str_cstr_length(rhs);
    
            if (lhs->count != rhs_length) return cutile_b8_false;
    
            for (u32 i = 0; i < rhs_length; ++i)
            {
                if (rhs[i] != lhs->data[i]) return cutile_b8_false;
            }
            return cutile_b8_true;
        }
    
        #define cutile_sub_str_to_unsigned_nb_m(res, str, offset, count)    \
        {                                                                   \
            res = 0;                                                        \
            u32 i = offset;                                                 \
            for (; i < count + offset; ++i)                                 \
            {                                                               \
                res *= 10;                                                  \
                res += str->data[i] - '0';                                  \
            }                                                               \
        }                                                                   \
        
        #define cutile_sub_str_to_signed_nb_m(res, str, offset, count)  \
        {                                                               \
            res = 0;                                                    \
            u32 i = offset;                                             \
            b8 neg = cutile_b8_false;                                   \
            if (str_at(s, i) == '-') {                                  \
                neg = cutile_b8_true;                                   \
                ++i;                                                    \
            }                                                           \
            for (; i < count + offset; ++i) {                           \
                res *= 10;                                              \
                res += s->data[i] - '0';                                \
            }                                                           \
            res = neg ? -res : res;                                     \
        }                                                               \
    
        u8 cutile_sub_str_to_u8(const cutile_string* s, u32 offset, u32 count) { u8 res; cutile_sub_str_to_unsigned_nb_m(res, s, offset, count); return res; }
    
        s8 cutile_sub_str_to_s8(const cutile_string* s, u32 offset, u32 count)  { s8 res; cutile_sub_str_to_signed_nb_m(res, s, offset, count); return res; }
    
        u16 cutile_sub_str_to_u16(const cutile_string* s, u32 offset, u32 count) { u16 res; cutile_sub_str_to_unsigned_nb_m(res, s, offset, count); return res; }
    
        s16 cutile_sub_str_to_s16(const cutile_string* s, u32 offset, u32 count) { s16 res; cutile_sub_str_to_signed_nb_m(res, s, offset, count); return res; }
    
        u32 cutile_sub_str_to_u32(const cutile_string* s, u32 offset, u32 count) { u32 res; cutile_sub_str_to_unsigned_nb_m(res, s, offset, count); return res; }
    
        s32 cutile_sub_str_to_s32(const cutile_string* s, u32 offset, u32 count) { s32 res; cutile_sub_str_to_signed_nb_m(res, s, offset, count); return res; }
    
        u64 cutile_sub_str_to_u64(const cutile_string* s, u32 offset, u32 count) { u64 res; cutile_sub_str_to_unsigned_nb_m(res, s, offset, count); return res; }
    
        s64 cutile_sub_str_to_s64(const cutile_string* s, u32 offset, u32 count) { s64 res; cutile_sub_str_to_signed_nb_m(res, s, offset, count); return res; }
    
        u8  cutile_str_to_u8(const cutile_string* s)
        {
            return cutile_sub_str_to_u8(s, 0, s->count);
        }
        s8  cutile_str_to_s8(const cutile_string* s)
        {
            return cutile_sub_str_to_s8(s, 0, s->count);
        }
        u16 cutile_str_to_u16(const cutile_string* s)
        {
            return cutile_sub_str_to_u16(s, 0, s->count);
        }
        s16 cutile_str_to_s16(const cutile_string* s)
        {
            return cutile_sub_str_to_s16(s, 0, s->count);
        }
        u32 cutile_str_to_u32(const cutile_string* s)
        {
            return cutile_sub_str_to_u32(s, 0, s->count);
        }
        s32 cutile_str_to_s32(const cutile_string* s)
        {
            return cutile_sub_str_to_s32(s, 0, s->count);
        }
        u64 cutile_str_to_u64(const cutile_string* s)
        {
            return cutile_sub_str_to_u64(s, 0, s->count);
        }
        s64 cutile_str_to_s64(const cutile_string* s)
        {
            return cutile_sub_str_to_s64(s, 0, s->count);
        }
    
        #include "number.h"
    
        #define cutile_unsigned_nb_to_str_m(nb, digits, allocator)          \
        {                                                                   \
            cutile_string out =                                             \
                cutile_create_sized_empty_str(digits, allocator);           \
            for (u32 i = digits; i > 0; --i)                                \
            {                                                               \
                out.data[i - 1] = nb % 10 + '0';                            \
                nb /= 10;                                                   \
            }                                                               \
            out.count = digits;                                             \
            return out;                                                     \
        }                                                                   \
    
        #define cutile_signed_nb_to_str_m(nb, digits, allocator)            \
        {                                                                   \
            s32 neg;                                                        \
            s32 mul;                                                        \
            cutile_string out;                                              \
            if (nb < 0)                                                     \
            {                                                               \
                out = cutile_create_sized_empty_str(digits+1, allocator);   \
                out.data[0] = '-';                                          \
                neg = 1;                                                    \
                mul = -1;                                                   \
            }                                                               \
            else                                                            \
            {                                                               \
                out = cutile_create_sized_empty_str(digits, allocator);     \
                neg = 0;                                                    \
                mul = 1;                                                    \
            }                                                               \
            for (u32 i = digits; i > 0; --i)                                \
            {                                                               \
                out.data[i - 1 + neg] = ((nb % 10) * mul) + '0';            \
                nb /= 10;                                                   \
            }                                                               \
            out.count = digits + neg;                                       \
            return out;                                                     \
        }                                                                   \
    
        cutile_string cutile_u8_to_str(u8 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u8_digits_m(nb, digits); cutile_unsigned_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_s8_to_str(s8 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s8_digits_m(nb, digits); cutile_signed_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_u16_to_str(u16 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u16_digits_m(nb, digits); cutile_unsigned_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_s16_to_str(s16 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s16_digits_m(nb, digits); cutile_signed_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_u32_to_str(u32 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u32_digits_m(nb, digits); cutile_unsigned_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_s32_to_str(s32 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s32_digits_m(nb, digits); cutile_signed_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_u64_to_str(u64 nb, cutile_allocator* allocator) { u32 digits; cutile_get_u64_digits_m(nb, digits); cutile_unsigned_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_s64_to_str(s64 nb, cutile_allocator* allocator) { u32 digits; cutile_get_s64_digits_m(nb, digits); cutile_signed_nb_to_str_m(nb, digits, allocator); }

        cutile_string cutile_f32_to_str(f32 nb, cutile_allocator* allocator)
        {
            s32 integer_part = cast(s32, nb);
            f32 float_part = nb - cast(f32, integer_part);
            // 7 decimal places.
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;

            cutile_string result = create_empty_str(allocator);
            cutile_s32_into_str(integer_part, &result);
            cutile_str_push_back(&result, '.');
            cutile_s32_into_str(cast(s64, float_part), &result);

            return result;
        }

        cutile_string cutile_f64_to_str(f64 nb, cutile_allocator* allocator)
        {
            s64 integer_part = cast(s64, nb);
            f64 float_part = nb - cast(f64, integer_part);
            // 17 decimal places.
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;

            cutile_string result = create_empty_str(allocator);
            cutile_s64_into_str(integer_part, &result);
            cutile_str_push_back(&result, '.');
            cutile_s64_into_str(cast(s64, float_part), &result);

            return result;
        }
    
        void cutile_u8_into_str(u8 nb, cutile_string* out) { cutile_u8_into_sub_str(nb, out, out->count); }
    
        void cutile_s8_into_str(s8 nb, cutile_string* out) { cutile_s8_into_sub_str(nb, out, out->count); }
    
        void cutile_u16_into_str(u16 nb, cutile_string* out) { cutile_u16_into_sub_str(nb, out, out->count); }
    
        void cutile_s16_into_str(s16 nb, cutile_string* out) { cutile_s16_into_sub_str(nb, out, out->count); }
    
        void cutile_u32_into_str(u32 nb, cutile_string* out) { cutile_u32_into_sub_str(nb, out, out->count); }

        void cutile_s32_into_str(s32 nb, cutile_string* out) { cutile_s32_into_sub_str(nb, out, out->count); }

        void cutile_u64_into_str(u64 nb, cutile_string* out) { cutile_u64_into_sub_str(nb, out, out->count); }

        void cutile_s64_into_str(s64 nb, cutile_string* out) { cutile_s64_into_sub_str(nb, out, out->count); }

        void cutile_f32_into_str(f32 nb, cutile_string* out)
        {
            s32 integer_part = cast(s32, nb);
            f32 float_part = nb - cast(f32, integer_part);
            // 7 decimal places.
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;

            cutile_s32_into_str(integer_part, out);
            cutile_str_push_back(out, '.');
            cutile_s32_into_str(cast(s64, float_part), out);
        }

        void cutile_f64_into_str(f64 nb, cutile_string* out)
        {
            s64 integer_part = cast(s64, nb);
            f64 float_part = nb - cast(f64, integer_part);
            // 17 decimal places.
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;
            float_part *= 10;

            cutile_s64_into_str(integer_part, out);
            cutile_str_push_back(out, '.');
            cutile_s64_into_str(cast(s64, float_part), out);
        }

        #define cutile_unsigned_nb_into_sub_str(nb, digits, str_ptr, index)    \
        {                                                                      \
            if (str_ptr->count + digits >= str_ptr->size)                      \
                cutile_resize_str(str_ptr, str_ptr->size + index + digits);    \
            for (u32 i = index; i < str_ptr->count; ++i)                       \
            {                                                                  \
                str_ptr->data[i + digits] = str_ptr->data[i];                  \
            }                                                                  \
            for (u32 i = index + digits; i > index; --i)                       \
            {                                                                  \
                str_ptr->data[i - 1] = nb % 10 + '0';                          \
                nb /= 10;                                                      \
            }                                                                  \
            str_ptr->count += digits;                                          \
        }                                                                      \
    
        #define cutile_signed_nb_into_sub_str(nb, digits, str_ptr, index)   \
        {                                                                   \
            u32 neg;                                                        \
            s32 mul;                                                        \
            if (nb < 0)                                                     \
            {                                                               \
                if (str_ptr->count + digits + 1 >= str_ptr->size)           \
                    cutile_resize_str(str_ptr, str_ptr->size + digits + 1); \
                for (u32 i = index; i < str_ptr->count; ++i)                \
                {                                                           \
                    str_ptr->data[i + digits + 1] = str_ptr->data[i];       \
                }                                                           \
                str_ptr->data[index] = '-';                                 \
                neg = 1;                                                    \
                mul = -1;                                                   \
            }                                                               \
            else                                                            \
            {                                                               \
                if (str_ptr->count + digits >= str_ptr->size)               \
                    cutile_resize_str(str_ptr, str_ptr->size + digits);     \
                for (u32 i = index; i < str_ptr->count; ++i)                \
                {                                                           \
                    str_ptr->data[i + digits] = str_ptr->data[i];           \
                }                                                           \
                neg = 0;                                                    \
                mul = 1;                                                    \
            }                                                               \
            for (u32 i = index + digits; i > index; --i)                    \
            {                                                               \
                str_ptr->data[i - 1 + neg] = ((nb % 10) * mul) + '0';       \
                nb /= 10;                                                   \
            }                                                               \
            str_ptr->count += digits + neg;                                 \
        }                                                                   \
    
        void cutile_u8_into_sub_str(u8 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_u8_digits_m(nb, digits); cutile_unsigned_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_s8_into_sub_str(s8 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_s8_digits_m(nb, digits); cutile_signed_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_u16_into_sub_str(u16 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_u16_digits_m(nb, digits); cutile_unsigned_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_s16_into_sub_str(s16 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_s16_digits_m(nb, digits); cutile_signed_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_u32_into_sub_str(u32 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_u32_digits_m(nb, digits); cutile_unsigned_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_s32_into_sub_str(s32 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_s32_digits_m(nb, digits); cutile_signed_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_u64_into_sub_str(u64 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_u64_digits_m(nb, digits); cutile_unsigned_nb_into_sub_str(nb, digits, out, index); }
    
        void cutile_s64_into_sub_str(s64 nb, cutile_string* out, u32 index) { u32 digits; cutile_get_s64_digits_m(nb, digits); cutile_signed_nb_into_sub_str(nb, digits, out, index); }
    
    #endif // CUTILE_IMPLEM

    #define CUTILE_STR_H
#endif

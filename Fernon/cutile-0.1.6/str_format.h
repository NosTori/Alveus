#ifndef CUTILE_STR_FORMAT_H

    #include "str.h"

    #ifndef CUTILE_CPP
        #error "str_format.h is only available for C++"
    #endif

    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(cutile_allocator* allocator, const char* fmt, Args ...args);

    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(const char* fmt, Args ...args);

    template <typename ...Args>
    maybe_inline void          cutile_format_str(cutile_string* out, const char* fmt, Args ...args);

    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(cutile_allocator* allocator, const cutile_string* fmt, Args ...args);

    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(const cutile_string* fmt, Args ...args);

    template <typename ...Args>
    maybe_inline void          cutile_format_str(cutile_string* out, const cutile_string* fmt, Args ...args);

    struct cutile_format_memory_to_str
    {
        const u8* buffer;
        u64 size;
    };

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define format_str(...) cutile_format_str(__VA_ARGS__)

        typedef cutile_format_memory_to_str format_memory_to_str;
    #endif

    // Implement this function if you want to be able to format other types.
    template <typename Arg>
    void cutile_format_arg_into_str(cutile_string* out, Arg);
    // Currently available implementations:
    template <> maybe_inline void cutile_format_arg_into_str<u8>(cutile_string*, u8);
    template <> maybe_inline void cutile_format_arg_into_str<s8>(cutile_string*, s8);
    template <> maybe_inline void cutile_format_arg_into_str<u16>(cutile_string*, u16);
    template <> maybe_inline void cutile_format_arg_into_str<s16>(cutile_string*, s16);
    template <> maybe_inline void cutile_format_arg_into_str<u32>(cutile_string*, u32);
    template <> maybe_inline void cutile_format_arg_into_str<s32>(cutile_string*, s32);
    template <> maybe_inline void cutile_format_arg_into_str<u64>(cutile_string*, u64);
    template <> maybe_inline void cutile_format_arg_into_str<s64>(cutile_string*, s64);
    template <> maybe_inline void cutile_format_arg_into_str<f32>(cutile_string*, f32);
    template <> maybe_inline void cutile_format_arg_into_str<f64>(cutile_string*, f64);
    template <> maybe_inline void cutile_format_arg_into_str<const char*>(cutile_string*, const char*);
    template <> maybe_inline void cutile_format_arg_into_str<cutile_string>(cutile_string*, cutile_string);
    template <> maybe_inline void cutile_format_arg_into_str<cutile_string*>(cutile_string*, cutile_string*);
    template <> maybe_inline void cutile_format_arg_into_str<const cutile_string*>(cutile_string*, const cutile_string*);
    template <> maybe_inline void cutile_format_arg_into_str<cutile_format_memory_to_str>(cutile_string*, cutile_format_memory_to_str);
    
    // IMPLEMENTATION BELOW:
    
    template <typename Arg>
    maybe_inline void cutile_format_next_arg_into_str(const char* fmt, cutile_string* out, Arg arg, u32* i, u32 len)
    {
        while (*i < len)
        {
            char c = fmt[*i];
            if (c == '%')
            {
                cutile_format_arg_into_str(out, arg);
                ++(*i);
                return;
            }
            else
            {
                cutile_str_push_back(out, c);
                ++(*i);
            }
        }
    }
    
    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(cutile_allocator* allocator, const char* fmt, Args ...args)
    {
        cutile_string str = cutile_create_empty_str(allocator);
        cutile_format_str(&str, fmt, args...);
        return str;
    }
    
    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(const char* fmt, Args ...args)
    {
        return cutile_format_str(cutile_default_allocator, fmt, args...);
    }
    
    template <typename ...Args>
    maybe_inline void cutile_format_str(cutile_string* out, const char* fmt, Args ...args)
    {
        u32 i = 0;
        u32 fmt_len = 0;
        while (fmt[fmt_len]) fmt_len++;
        (cutile_format_next_arg_into_str(fmt, out, args, &i, fmt_len), ...);
        if (i < fmt_len)
        {
            cutile_str_push_back_buf(out, (u8*)fmt + i, fmt_len - i);
        }
    }
    
    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(cutile_allocator* allocator, const cutile_string* fmt, Args ...args)
    {
        cutile_string str = cutile_create_empty_str(allocator);
        cutile_format_str(&str, fmt, args...);
        return str;
    }

    template <typename ...Args>
    maybe_inline cutile_string cutile_format_str(const cutile_string* fmt, Args ...args)
    {
        return cutile_format_str(cutile_default_allocator, fmt, args...);
    }
    
    template <typename ...Args>
    maybe_inline void cutile_format_str(cutile_string* out, const cutile_string* fmt, Args ...args)
    {
        u32 i = 0;
        (cutile_format_next_arg_into_str((const char*)fmt->data, out, args, &i, fmt->count), ...);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<u64>(cutile_string* out, u64 arg)
    {
        cutile_u64_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<s64>(cutile_string* out, s64 arg)
    {
        cutile_s64_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<u32>(cutile_string* out, u32 arg)
    {
        cutile_u32_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<s32>(cutile_string* out, s32 arg)
    {
        cutile_s32_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<u16>(cutile_string* out, u16 arg)
    {
        cutile_u16_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<s16>(cutile_string* out, s16 arg)
    {
        cutile_s16_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<u8>(cutile_string* out, u8 arg)
    {
        cutile_u8_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<s8>(cutile_string* out, s8 arg)
    {
        cutile_s8_into_str(arg, out);
    }

    template <> maybe_inline void cutile_format_arg_into_str<f32>(cutile_string* out, f32 arg)
    {
        cutile_f32_into_str(arg, out);
    }

    template <> maybe_inline void cutile_format_arg_into_str<f64>(cutile_string* out, f64 arg)
    {
        cutile_f64_into_str(arg, out);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<const char*>(cutile_string* out, const char* arg)
    {
        cutile_str_push_back_cstr(out, arg);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<char*>(cutile_string* out, char* arg)
    {
        cutile_str_push_back_cstr(out, arg);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<cutile_string>(cutile_string* out, cutile_string arg)
    {
        cutile_format_arg_into_str(out, &arg);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<cutile_string*>(cutile_string* out, cutile_string* arg)
    {
        cutile_str_push_back_str(out, arg);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<const cutile_string*>(cutile_string* out, const cutile_string* arg)
    {
        cutile_str_push_back_str(out, arg);
    }

    template <> 
    maybe_inline void cutile_format_arg_into_str<cutile_string_view>(cutile_string* out, cutile_string_view sv)
    {
        cutile_str_push_back_buf(out, (u8*)sv.data, sv.count);
    }

    template <>
    maybe_inline void cutile_format_arg_into_str<void*>(cutile_string* out, void* arg)
    {
        cutile_format_arg_into_str(out, (u64)arg);
    }
    
    template <> 
    maybe_inline void cutile_format_arg_into_str<cutile_format_memory_to_str>(cutile_string* out, cutile_format_memory_to_str arg)
    {
        cutile_str_push_back_buf(out, arg.buffer, arg.size);
    }

    #define CUTILE_STR_FORMAT_H
#endif

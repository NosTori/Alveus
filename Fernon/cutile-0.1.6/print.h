#ifndef CUTILE_PRINT_H

    // This API has optional functions using cutile_string.
    // In order to compile them you need to define CUTILE_IMPLEM_PRINT_STRING_API.

    #include "cutile.h"

    // Type defined in str.h:
    typedef struct cutile_string    cutile_string;

    CUTILE_C_API void cutile_print_cstr(const char* cstr);
    CUTILE_C_API void cutile_print_str(const cutile_string* str);
    CUTILE_C_API void cutile_println_cstr(const char* cstr);
    CUTILE_C_API void cutile_println_str(const cutile_string* str);

    #ifdef CUTILE_CPP
        #include "cxx.h" // maybe_inline
        #include "str_format.h"

        typedef struct cutile_allocator cutile_allocator; // Defined in memory.h

        maybe_inline void cutile_print(cutile_string* s)   { cutile_print_str(s); }
        maybe_inline void cutile_print(const char* s)      { cutile_print_cstr(s); }
        maybe_inline void cutile_println(cutile_string* s) { cutile_println_str(s); }
        maybe_inline void cutile_println(const char* s)    { cutile_println_cstr(s); }

        template <typename ...Args>
        maybe_inline void cutile_print_fmt(const char* fmt, Args ...args) { cutile_print_fmt(cutile_default_allocator, fmt, args...); }
        template <typename ...Args>
        maybe_inline void cutile_print_fmt(cutile_allocator* allocator, const char* fmt, Args ...args) 
        {
            string s = cutile_format_str(allocator, fmt, args...);
            cutile_print(&s);
            cutile_destroy_str(&s);
        }

        template <typename ...Args>
        maybe_inline void cutile_println_fmt(const char* fmt, Args ...args) { cutile_println_fmt(cutile_default_allocator, fmt, args...); }
        template <typename ...Args>
        maybe_inline void cutile_println_fmt(cutile_allocator* allocator, const char* fmt, Args ...args)
        {
            string s = cutile_format_str(allocator, fmt, args...);
            cutile_println(&s);
            cutile_destroy_str(&s);
        }
    #endif

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define print_cstr(param)   cutile_print_cstr(param);
        #define print_str(param)    cutile_print_str(param);
        #define println_cstr(param) cutile_println_cstr(param);
        #define println_str(param)  cutile_println_str(param);

        #ifdef CUTILE_CPP
            #define print(...)   cutile_print(__VA_ARGS__)
            #define println(...) cutile_println(__VA_ARGS__)

            #define print_fmt(...) cutile_print_fmt(__VA_ARGS__)
            #define println_fmt(...) cutile_println_fmt(__VA_ARGS__)
        #endif
    #endif

    #ifdef CUTILE_IMPLEM
        #include "cxx.h"

        #if WINDOWS
            #include <windows.h>
        #elif UNIX_LIKE
            #include <unistd.h>
        #endif

        void cutile_print_cstr(const char* cstr)
        {
            u32 len = 0; while(cstr[len]) len++;
            #if WINDOWS
                HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
                if (out && out != INVALID_HANDLE_VALUE) 
                {
                    DWORD written;
                    WriteConsoleA(out, cstr, len, &written, NULL);
                }
            #elif UNIX_LIKE
                write(1, cstr, len);
            #else
                #error "Unsupported platform."
            #endif
        }

        void cutile_println_cstr(const char* cstr)
        {
            cutile_print_cstr(cstr);
            cutile_print_cstr("\n");
        }

    #endif // CUTILE_IMPLEM

    #ifdef CUTILE_IMPLEM_PRINT_STRING_API
        #include "str.h"
    
        void cutile_print_str(const cutile_string* str)
        {
            #if WINDOWS
                HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
                if (out && out != INVALID_HANDLE_VALUE) 
                {
                    DWORD written;
                    WriteConsoleA(out, str->data, str->count, &written, NULL);
                }
            #elif UNIX_LIKE
                write(1, str->data, str->count);
            #else
                #error "Unsupported platform."
            #endif
        }

        void cutile_println_str(const cutile_string* str)
        {
            cutile_print_str(str);
            cutile_print_cstr("\n");
        }

    #endif // CUTILE_IMPLEM_PRINT_STRING_API

    #define CUTILE_PRINT_H
#endif

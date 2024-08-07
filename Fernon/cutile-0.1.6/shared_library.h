#ifndef CUTILE_SHARED_LIBRARY_H

    #include "cxx.h"

    typedef struct cutile_shared_library
    {
        void* handle;
    } cutile_shared_library;

    // On Windows and Linux, sets shared_library.handle to nullptr if the function fails.
    CUTILE_C_API cutile_shared_library  cutile_load_shared_library(const char* shared_library_path);
    CUTILE_C_API void                   cutile_unload_shared_library(cutile_shared_library*);

    // On Windows and Linux, returns nullptr if the function fails.
    CUTILE_C_API void* cutile_get_shared_library_proc(cutile_shared_library*, const char* proc_name);
    #define            cutile_get_shared_library_T_proc(T, sl, name) (T)cutile_get_shared_library_proc(sl, name)

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        typedef cutile_shared_library shared_library;

        #define load_shared_library(path) cutile_load_shared_library(path)
        #define unload_shared_library(sl) cutile_unload_shared_library(sl)

        #define get_shared_library_proc(sl, proc_name) cutile_get_shared_library_proc(sl, proc_name)
        #define get_shared_library_T_proc(T, sl, proc_name) cutile_get_shared_library_T_proc(T, sl, proc_name)
    #endif

    #ifdef CUTILE_IMPLEM
        #if WINDOWS
            #include <windows.h>
        #elif LINUX
            #include <dlfcn.h>
        #else
            #error "shared_library.h: Unsupported platform."
        #endif
        
        cutile_shared_library cutile_load_shared_library(const char* shared_library_path)
        {
            cutile_shared_library result;
            #if WINDOWS
                result.handle = LoadLibraryA(shared_library_path);
            #elif LINUX
                result.handle = dlopen(shared_library_path, RTLD_LAZY); /* RTLD_NOW is also possible but I still don't understand how it works. What are the pros and cons of lazy loading and immediate loading ? */
            #endif

            return result;
        }
    
        void cutile_unload_shared_library(cutile_shared_library* sl)
        {
            #if WINDOWS
                FreeLibrary((HMODULE)sl->handle);
            #elif LINUX
                dlclose(sl->handle);
            #endif
        }
    
        void* cutile_get_shared_library_proc(cutile_shared_library* sl, const char* proc_name)
        {
            #if WINDOWS
                return GetProcAddress((HMODULE)sl->handle, proc_name);
            #elif LINUX
                return dlsym(sl->handle, proc_name);
            #endif
        }
    #endif // CUTILE_IMPLEM

    #define CUTILE_SHARED_LIBRARY_H
#endif

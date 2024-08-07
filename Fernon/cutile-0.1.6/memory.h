
#ifndef CUTILE_MEMORY_H

    #include "cxx.h"

    #define cutile_fill_memory_m(data, count, value)
    #define cutile_copy_memory_m(out, in, count)

    CUTILE_C_API b8 cutile_memory_equals(const u8* lhs, const u8* rhs, u64 nb_bytes);

    #define cutile_memory_equals_m(lhs, rhs, count, out)

    // Performs memory allocations/deallocations according to your current platform.
    // Will use HeapAllocate for Win32. For other platforms it will use malloc/free.
    CUTILE_C_API void* cutile_default_allocate(u64 size);
    CUTILE_C_API void  cutile_default_deallocate(void* ptr);

    typedef struct cutile_allocator cutile_allocator;
    typedef struct cutile_allocator
    {
        void* (*allocate)(cutile_allocator*, u64 size);
        void  (*deallocate)(cutile_allocator*, void* ptr);
    } cutile_allocator;

    #define cutile_allocator_prelude_m cutile_allocator __allocator_base

    #define cutile_allocate_m(allocator_ptr, size)            (allocator_ptr)->allocate(allocator_ptr, (size))
    #define cutile_allocate_T_m(allocator_ptr, T)             (T*)cutile_allocate_m(allocator_ptr, sizeof(T))
    #define cutile_allocate_many_T_m(allocator_ptr, T, count) (T*)cutile_allocate_m(allocator_ptr, sizeof(T) * (count))

    #define cutile_deallocate_m(allocator_ptr, ptr) (allocator_ptr)->deallocate(allocator_ptr, ptr)

    maybe_inline void* cutile_allocate(cutile_allocator* allocator, u64 size) { return allocator->allocate(allocator, size); }
    maybe_inline void cutile_deallocate(cutile_allocator* allocator, void* ptr) { allocator->deallocate(allocator, ptr); }

    // TODO: "heap_allocator" is a wrong name for the moment: it uses a heap on Win32 but this might not be the case for other platforms where we are using malloc/free which might not be implemented using a heap. Implement platform independant heap allocator.
    typedef struct
    {
        cutile_allocator_prelude_m;

        void* heap;
    } cutile_heap_allocator;

    CUTILE_C_API cutile_heap_allocator cutile_create_heap_allocator(void* heap);
    CUTILE_C_API cutile_heap_allocator cutile_create_default_heap_allocator();

    typedef struct
    {
        cutile_allocator_prelude_m;
    
        u8* buffer;
        u64 buffer_size;
        u64 offset;
    } cutile_arena_allocator;

    CUTILE_C_API cutile_arena_allocator cutile_create_arena_allocator(u8* buffer, u64 buffer_size);
    CUTILE_C_API void                   cutile_reset_arena_allocator(cutile_arena_allocator*);

    CUTILE_C_API cutile_allocator* cutile_default_allocator;
    #define cutile_set_default_allocator_m(allocator_ptr) cutile_default_allocator = (cutile_allocator*)allocator_ptr

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define fill_memory_m(out, count, value)        cutile_fill_memory_m(out, count, value)
        #define copy_memory_m(out, in, count)           cutile_copy_memory_m(out, in, count)

        #define memory_equals(lhs, rhs, nb_bytes)       cutile_memory_equals(lhs, rhs, nb_bytes)
        #define memory_equals_m(lhs, rhs, count, out)   cutile_memory_equals_m(lhs, rhs, count, out)

        #define default_allocate(size) cutile_default_allocate(size)
        #define default_deallocate(ptr) cutile_default_deallocate(ptr)


        typedef cutile_allocator allocator;

        #define allocator_prelude_m cutile_allocator_prelude_m

        #define allocate_m(allocator_ptr, size)               cutile_allocate_m(allocator_ptr, size)
        #define allocate_T_m(allocator_ptr, T)                cutile_allocate_T_m(allocator_ptr, T)
        #define allocate_many_T_m(allocator_ptr, T, count)    cutile_allocate_many_T_m(allocator_ptr, T, count)

        #define deallocate_m(allocator_ptr, ptr) cutile_deallocate_m(allocator_ptr, ptr)

        maybe_inline void* allocate(cutile_allocator* allocator, u64 size) { return cutile_allocate(allocator, size); }
        maybe_inline void  deallocate(cutile_allocator* allocator, void* ptr) { cutile_deallocate(allocator, ptr); }

        typedef cutile_heap_allocator heap_allocator;

        #define create_heap_allocator(heap_ptr) cutile_create_heap_allocator(heap_ptr)
        #define create_default_heap_allocator() cutile_create_default_heap_allocator();

        typedef cutile_arena_allocator arena_allocator;

        #define create_arena_allocator(buffer, buffer_size) cutile_create_arena_allocator(buffer, buffer_size)
        #define reset_arena_allocator(arena_allocator_ptr)  cutile_reset_arena_allocator(arena_allocator_ptr)

        #define default_allocator cutile_default_allocator
        #define set_default_allocator_m(allocator_ptr) cutile_set_default_allocator_m(allocator_ptr)
    #endif

    #undef  cutile_fill_memory_m
    #define cutile_fill_memory_m(data, count, value)        \
    {                                                       \
        for (u32 i = 0; i < count; i++) (data)[i] = value;  \
    }                                                       \

    #undef  cutile_copy_memory_m
    #define cutile_copy_memory_m(out, in, count)            \
    {                                                       \
        for (u32 i = 0; i < count; i++) (out)[i] = (in)[i]; \
    }                                                       \

    #undef  cutile_memory_equals_m
    #define cutile_memory_equals_m(lhs, rhs, count, out)                \
    {                                                                   \
        out = cutile_b8_true;                                           \
        for (u32 i = 0; i < count; ++i)                                 \
        {                                                               \
            if ((lhs)[i] != (rhs)[i]) { out = cutile_b8_false; break; } \
        }                                                               \
    }                                                                   \

    #ifdef CUTILE_IMPLEM
        #ifdef _WIN32
            #include <windows.h>
        #else 
            #include <stdlib.h>  // malloc, free. TODO: Implement for other platforms instead of using lib c.
        #endif

        #include "number.h"

        b8 cutile_memory_equals(const u8* lhs, const u8* rhs, u64 nb_bytes)
        {
            b8 res;
            cutile_memory_equals_m(lhs, rhs, nb_bytes, res);
            return res;
        }

        void* cutile_default_allocate(u64 size)
        {
            void* ptr;
            #ifdef _WIN32
                ptr = HeapAlloc(GetProcessHeap(), 0, size);
            #else
                ptr = malloc(size); // TODO: Implement for other platforms.
            #endif
    
            return ptr;
        }
    
        void cutile_default_deallocate(void* ptr)
        {
            #ifdef _WIN32
                HeapFree(GetProcessHeap(), 0, ptr);
            #else
                free(ptr); // TODO: Implement for other platforms.
            #endif
        }

        internal void* __cutile_heap_allocator_allocate(cutile_allocator* opaque_allocator, u64 size)
        {
            cutile_heap_allocator* allocator = (cutile_heap_allocator*)opaque_allocator;
            #ifdef _WIN32
                return HeapAlloc(allocator->heap, 0, size);
            #else
                return malloc(size); // TODO: Implement for other platforms.
            #endif
        }

        internal void __cutile_heap_allocator_deallocate(cutile_allocator* opaque_allocator, void* ptr)
        {
            cutile_heap_allocator* allocator = (cutile_heap_allocator*)opaque_allocator;
            #ifdef _WIN32
                HeapFree(allocator->heap, 0, ptr);
            #else
                free(ptr); // TODO: Implement for other platforms.
            #endif
        }
    
        cutile_heap_allocator cutile_create_heap_allocator(void* heap)
        {
            cutile_heap_allocator res =
            {
                .__allocator_base = 
                {
                    .allocate = &__cutile_heap_allocator_allocate, 
                    .deallocate = &__cutile_heap_allocator_deallocate 
                },
                #ifdef _WIN32
                    .heap = heap
                #endif
            };
            return res;
        }

        cutile_heap_allocator cutile_create_default_heap_allocator()
        {
            #ifdef _WIN32
                return cutile_create_heap_allocator(GetProcessHeap());
            #else
                return cutile_create_heap_allocator(nullptr);
            #endif
        }

        internal void* __cutile_arena_allocate(cutile_allocator* opaque_arena, u64 size)
        {
            cutile_arena_allocator* arena = (cutile_arena_allocator*)opaque_arena;
            if (arena->offset + size >= arena->buffer_size) return nullptr;
            void* ptr = arena->buffer + arena->offset;
            arena->offset += size;
            return ptr;
        }

        internal void __cutile_arena_deallocate(cutile_allocator* opaque_arena, void* f)
        {
        }

        cutile_arena_allocator cutile_create_arena_allocator(u8* buffer, u64 buffer_size)
        {
            cutile_arena_allocator result =
            {
                { &__cutile_arena_allocate, &__cutile_arena_deallocate },
                buffer, buffer_size, 0
            };
            return result;
        }

        void cutile_reset_arena_allocator(cutile_arena_allocator* arena)
        {
            arena->offset = 0;
        }

    #endif // CUTILE_IMPLEM

    #define CUTILE_MEMORY_H
#endif

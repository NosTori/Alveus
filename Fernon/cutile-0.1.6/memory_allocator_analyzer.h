// TODO: This API is a first draft, let's think later (or not) of a clever design...

#ifndef CUTILE_MEMORY_ALLOCATOR_ANALYZER_H

    #ifndef _WIN32
        #error "Only WIN32 platforms are supported at the moment."
    #endif

    #include "stacktrace.h"

    cutile_generate_array_m(cutile_stacktrace);

    typedef enum
    {
        cutile_allocation_info_status_available,
        cutile_allocation_info_status_unavailable,
        cutile_allocation_info_status_invalid_address,
        cutile_allocation_info_status_double_free,
    } cutile_allocation_info_status;

    typedef struct
    {
        void*                           address;
        u64                             size;

        cutile_stacktrace               stacktrace;
        cutile_stacktrace_array         free_stacktraces;
    
        cutile_allocation_info_status   status;
    } cutile_allocation_info;

    cutile_generate_array_m(cutile_allocation_info);

    typedef struct cutile_allocation_table // Does not compile with C++ MSVC if I omit the struct name: it could not find the type name in some functions... I absolutely don't know why ???
    {
        cutile_allocation_info_array allocations;
        u64                          total_allocated;
        u64                          total_freed;
    } cutile_allocation_table;

    // The allocator will be used to allocate data required to store allocations information. For obvious reason, it should be a different allocator than the ones being analyzed :).
    CUTILE_C_API cutile_allocation_table cutile_start_allocators_analysis(cutile_allocator*);
    #define                              cutile_start_allocators_analysis_m(allocator_ptr)
    CUTILE_C_API void                    cutile_finish_allocators_analysis(cutile_allocation_table*);

    // Call those functions in your own allocator in order to update allocation information in the table.
    void cutile_add_new_alloc_info(cutile_allocation_table* table, u64 size, void* address);
    b8   cutile_try_remove_alloc_info(cutile_allocation_table* table, void* address);

    typedef struct
    {
        cutile_allocator_prelude_m;

        cutile_heap_allocator    heap_allocator;
        cutile_allocation_table* table;

        void (*bad_deallocate_handler)(struct cutile_allocation_table*, void*);
    } cutile_analyzable_heap_allocator;
    cutile_analyzable_heap_allocator cutile_create_analyzable_heap_allocator(cutile_allocation_table*);

    #ifdef CUTILE_IMPLEM

        void cutile_add_new_alloc_info(cutile_allocation_table* table, u64 size, void* address)
        {
            cutile_allocation_info* alloc_info = nullptr;

            // Search for an available node.
            for (u32 i = 0; i < table->allocations.count; ++i)
            {
                if (table->allocations.data[i].status == cutile_allocation_info_status_available)
                {
                    alloc_info = &table->allocations.data[i];
                    cutile_clear_cutile_stacktrace(&alloc_info->stacktrace);
                    cutile_clear_cutile_stacktrace_array(&alloc_info->free_stacktraces);
                    break;
                }
            }

            // No available node found so add a new one.
            if (alloc_info == nullptr)
            {
                cutile_allocation_info new_elem;
                new_elem.stacktrace = cutile_get_stacktrace(1, u16_max, table->allocations.allocator);
                new_elem.free_stacktraces = cutile_create_cutile_stacktrace_array(2, 2, table->allocations.allocator);
                cutile_cutile_allocation_info_array_push(&table->allocations, new_elem);
                alloc_info = &table->allocations.data[table->allocations.count - 1];
            }
            else cutile_fill_stacktrace(&alloc_info->stacktrace, 1, u16_max);

            alloc_info->status = cutile_allocation_info_status_unavailable;
            alloc_info->address = address;
            alloc_info->size = size;

            table->total_allocated += size;
        }

        b8 cutile_try_remove_alloc_info(cutile_allocation_table* table, void* address)
        {
            cutile_stacktrace st = cutile_get_stacktrace(1, u16_max, table->allocations.allocator);
            for (u32 i = 0; i < table->allocations.count; ++i)
            {
                cutile_allocation_info* alloc_info = &table->allocations.data[i];
                if (alloc_info->address == address)
                {
                    cutile_stacktrace_array_push(&alloc_info->free_stacktraces, st);
                    switch (alloc_info->status)
                    {
                        case cutile_allocation_info_status_unavailable:
                            table->total_freed += alloc_info->size;
                            alloc_info->status = cutile_allocation_info_status_available;
                            return b8_true;
                        case cutile_allocation_info_status_available:
                        case cutile_allocation_info_status_double_free:
                            alloc_info->status = cutile_allocation_info_status_double_free;
                            return b8_false;
                        case cutile_allocation_info_status_invalid_address:
                            return b8_false;
                    }
                }
            }

            // Address never allocated!!!
            cutile_allocation_info new_elem;
            new_elem.free_stacktraces = cutile_create_cutile_stacktrace_array(2, 2, table->allocations.allocator);
            new_elem.status = cutile_allocation_info_status_invalid_address;
            new_elem.address = address;
            new_elem.size = 0;
            cutile_cutile_stacktrace_array_push(&new_elem.free_stacktraces, st);
            cutile_cutile_allocation_info_array_push(&table->allocations, new_elem);
            return b8_false;
        }

        cutile_allocation_table cutile_start_allocator_analysis(cutile_allocator* allocatorrr)
        {
            cutile_allocation_table result;

            u32 s = sizeof(cutile_allocation_info);
            result.allocations = cutile_create_cutile_allocation_info_array(20, 20, allocatorrr);
            result.total_allocated = 0;
            result.total_freed = 0;

            return result;
        }

        internal void cutile_destroy_allocation_info(cutile_allocation_info* inf)
        {
            cutile_destroy_stacktrace(&inf->stacktrace);
            cutile_destroy_cutile_stacktrace_array_deeply(&inf->free_stacktraces, &cutile_destroy_stacktrace);
        }

        void cutile_finish_allocators_analysis(cutile_allocation_table* table)
        {
            cutile_destroy_cutile_allocation_info_array_deeply(&table->allocations, &cutile_destroy_allocation_info);
        }

        internal void* cutile_analyzable_heap_allocator_allocate(cutile_allocator* opaque_wrapper_allocator, u64 size)
        {
            cutile_analyzable_heap_allocator* wrapper = (cutile_analyzable_heap_allocator*)opaque_wrapper_allocator;

            void* result = cutile_allocate_m((cutile_allocator*)(&wrapper->heap_allocator), size);
            cutile_add_new_alloc_info(wrapper->table, size, result);

            return result;
        }

        internal void cutile_analyzable_heap_allocator_deallocate(cutile_allocator* opaque_wrapper_allocator, void* ptr)
        {
            cutile_analyzable_heap_allocator* wrapper = (cutile_analyzable_heap_allocator*)opaque_wrapper_allocator;

            if (cutile_try_remove_alloc_info(wrapper->table, ptr))
            {
                cutile_deallocate_m((cutile_allocator*)(&wrapper->heap_allocator), ptr);
            }
            else
            {
                if (wrapper->bad_deallocate_handler) wrapper->bad_deallocate_handler(wrapper->table, ptr);
            }
        }

        cutile_analyzable_heap_allocator cutile_create_analyzable_heap_allocator(cutile_allocation_table* tbl)
        {
            cutile_analyzable_heap_allocator result;
            result.__allocator_base.allocate = &cutile_analyzable_heap_allocator_allocate;
            result.__allocator_base.deallocate = &cutile_analyzable_heap_allocator_deallocate;
            result.heap_allocator = cutile_create_default_heap_allocator();
            result.table = tbl;
            result.bad_deallocate_handler = nullptr;
            return result;
        }

    #endif // CUTILE_IMPLEM

    #undef  cutile_start_allocators_analysis_m
    #define cutile_start_allocators_analysis_m(allocator_ptr) cutile_start_allocator_analysis((allocator*)allocator_ptr)

    #define CUTILE_MEMORY_ALLOCATOR_ANALYZER_H
#endif

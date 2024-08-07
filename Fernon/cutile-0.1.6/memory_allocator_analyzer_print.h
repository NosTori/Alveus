#ifndef CUTILE_MEMORY_ALLOCATOR_ANALYZER_PRINT_H

    #include "memory_allocator_analyzer.h"
    #include "print.h"
    #include "str.h"
    
    maybe_inline void cutile_print_allocation_table(cutile_allocation_table* status, cutile_allocator* allocator)
    {
        cutile_string str = cutile_create_sized_empty_str(1024, allocator);
    
        for (u32 i = 0; i < status->allocations.count; ++i)
        {
            cutile_allocation_info* alloc_info = &status->allocations.data[i];
    
            if (alloc_info->status == cutile_allocation_info_status_unavailable)
            {
                cutile_str_push_back_cstr(&str, "Block of size ");
                cutile_u64_into_str(alloc_info->size, &str);
                cutile_str_push_back_cstr(&str, " not freed at address ");
                cutile_u64_into_str((u64)alloc_info->address, &str);
                cutile_str_push_back_cstr(&str, ":\n");
                for (u32 i = 0; i < alloc_info->stacktrace.count; ++i)
                {
                    cutile_stacktrace_frame* stacktrace_elem = &alloc_info->stacktrace.data[i];
                    cutile_str_push_back_cstr(&str, "\t ");
                    cutile_str_push_back_cstr(&str, stacktrace_elem->filename);
                    cutile_str_push_back(&str, '.');
                    cutile_u32_into_str(stacktrace_elem->line, &str);
                    cutile_str_push_back_cstr(&str, " (");
                    cutile_str_push_back_cstr(&str, stacktrace_elem->symbol_name);
                    cutile_str_push_back_cstr(&str, ")\n");
                }
            }
            else if (alloc_info->status == cutile_allocation_info_status_invalid_address)
            {
                cutile_str_push_back_cstr(&str, "Invalid free of ");
                cutile_u64_into_str((u64)alloc_info->address, &str);
                cutile_str_push_back_cstr(&str, ":\n");
                for (u32 i = 0; i < alloc_info->free_stacktraces.count; ++i)
                {
                    cutile_str_push_back_cstr(&str, "\tDeallocation ");
                    cutile_u64_into_str(i, &str);
                    cutile_str_push_back_cstr(&str, ":\n");
    
                    cutile_stacktrace* st = &alloc_info->free_stacktraces.data[i];
                    for (u32 i = 0; i < st->count; ++i)
                    {
                        cutile_stacktrace_frame* stacktrace_elem = &st->data[i];
                        cutile_str_push_back_cstr(&str, "\t\t ");
                        cutile_str_push_back_cstr(&str, stacktrace_elem->filename);
                        cutile_str_push_back(&str, '.');
                        cutile_u32_into_str(stacktrace_elem->line, &str);
                        cutile_str_push_back_cstr(&str, " (");
                        cutile_str_push_back_cstr(&str, stacktrace_elem->symbol_name);
                        cutile_str_push_back_cstr(&str, ")\n");
                    }
                }
            }
            else if (alloc_info->status == cutile_allocation_info_status_double_free)
            {
                cutile_str_push_back_cstr(&str, "Double free of ");
                cutile_u64_into_str((u64)alloc_info->address, &str);
                cutile_str_push_back_cstr(&str, ":\n");
                for (u32 i = 0; i < alloc_info->free_stacktraces.count; ++i)
                {
                    cutile_str_push_back_cstr(&str, "\tDeallocation ");
                    cutile_u64_into_str(i, &str);
                    cutile_str_push_back_cstr(&str, ":\n");
    
                    cutile_stacktrace* st = &alloc_info->free_stacktraces.data[i];
                    for (u32 i = 0; i < st->count; ++i)
                    {
                        cutile_stacktrace_frame* stacktrace_elem = &st->data[i];
                        cutile_str_push_back_cstr(&str, "\t\t ");
                        cutile_str_push_back_cstr(&str, stacktrace_elem->filename);
                        cutile_str_push_back(&str, '.');
                        cutile_u32_into_str(stacktrace_elem->line, &str);
                        cutile_str_push_back_cstr(&str, " (");
                        cutile_str_push_back_cstr(&str, stacktrace_elem->symbol_name);
                        cutile_str_push_back_cstr(&str, ")\n");
                    }
                }
            }
        }
    
        cutile_str_push_back_cstr(&str, "Total allocated: ");
        cutile_u64_into_str(status->total_allocated, &str);
        cutile_str_push_back_cstr(&str, " bytes.\n");
        cutile_str_push_back_cstr(&str, "Total freed: ");
        cutile_u64_into_str(status->total_freed, &str);
        cutile_str_push_back_cstr(&str, " bytes.\n");
    
        cutile_print_str(&str);
        cutile_destroy_str(&str);
    }

    #define CUTILE_MEMORY_ALLOCATOR_ANALYZER_PRINT_H
#endif

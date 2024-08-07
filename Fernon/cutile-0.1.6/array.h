#ifndef CUTILE_ARRAY_H
    #include "memory.h"

    #define cutile_fixed_array_length_m(arr)  (sizeof(arr)/sizeof(arr[0]))

    #define cutile_array_view(type) type##_array_view

    #define cutile_generate_array_view_m(type) cutile_generate_named_array_view_m(type, type##_array_view)
    #define cutile_generate_named_array_view_m(type, name)  \
        typedef struct                                      \
        {                                                   \
            const type* data;                               \
            u32   count;                                    \
        } name;                                             \

    #define cutile_generate_array_m(type) cutile_generate_named_array_m(type, type##_array)

    #define cutile_array(type) type##_array
    
    #ifndef CUTILE_API_NO_SHORT_NAMES
        #define fixed_array_length_m(arr) cutile_fixed_array_length_m(arr)
        #define array_view(type) cutile_array_view(type)
        #define array(type) cutile_array(type)
        #define cutile_generate_named_array_m(type, name)               \
            cutile_generate_named_array_interface_m(type, name)         \
            cutile_generate_named_array_short_interface_m(type, name)   \
            cutile_generate_named_array_implementation_m(type, name)
    #else
        #define cutile_generate_named_array_m(type, name)               \
            cutile_generate_named_array_interface_m(type, name)         \
            cutile_generate_named_array_implementation_m(type, name)
    #endif

    #define cutile_generate_array_interface_m(type) cutile_generate_named_array_interface_m(type, type##_array)

    #define cutile_generate_named_array_interface_m(type, name)                                         \
        typedef struct                                                                                  \
        {                                                                                               \
            type*              data;                                                                    \
            u32                count;                                                                   \
            u32                size;                                                                    \
            u32                increment;                                                               \
            cutile_allocator*  allocator;                                                               \
        } name;                                                                                         \
                                                                                                        \
        maybe_inline name  cutile_create_##name(u32 size, u32 increment, cutile_allocator* allocator);  \
        maybe_inline void  cutile_destroy_##name(name* array);                                          \
        maybe_inline void  cutile_destroy_##name##_deeply(name* array, void(*)(type*));                 \
                                                                                                        \
        maybe_inline void  cutile_resize_##name(name* array, u32 new_size);                             \
                                                                                                        \
        maybe_inline void  cutile_##name##_push(name* array, type val);                                 \
        maybe_inline type* cutile_##name##_push_empty(name* array);                                     \
        maybe_inline void  cutile_##name##_push_repeated(name* array, type val, u32 count);             \
        maybe_inline void  cutile_##name##_push_buffer(name* array, type* buf, u32 count);              \
        maybe_inline void  cutile_##name##_push_array(name* array, name* other);                        \
                                                                                                        \
        maybe_inline void  cutile_##name##_pop(name* array);                                            \
        maybe_inline void  cutile_##name##_remove(name* array, u32 index);                              \
        maybe_inline void  cutile_clear_##name(name* array);                                            \
        maybe_inline void  cutile_clear_##name##_deeply(name* array, void(*dtor)(type*));               \
                                                                                                        \
        maybe_inline void  cutile_reverse_##name##_slice(name* array, u32 offset, u32 count);           \
        maybe_inline void  cutile_reverse_##name(name* array);                                          \
                                                                                                        \

    #define cutile_generate_named_array_short_interface_m(type, name)                                                                                       \
        maybe_inline name  create_##name(u32 size, u32 increment, cutile_allocator* allocator) { return cutile_create_##name(size, increment, allocator); } \
        maybe_inline void  destroy_##name(name* array) { cutile_destroy_##name(array); }                                                                    \
        maybe_inline void  destroy_##name##_deeply(name* array, void(*dtor)(type*)) { cutile_destroy_##name##_deeply(array, dtor); }                        \
                                                                                                                                                            \
        maybe_inline void  resize_##name(name* array, u32 new_size) { cutile_resize_##name(array, new_size); }                                              \
                                                                                                                                                            \
        maybe_inline void  name##_push(name* array, type val) { cutile_##name##_push(array, val); }                                                         \
        maybe_inline type* name##_push_empty(name* array) { return cutile_##name##_push_empty(array); }                                                     \
        maybe_inline void  name##_push_repeated(name* array, type val, u32 count) { cutile_##name##_push_repeated(array, val, count); }                     \
        maybe_inline void  name##_push_buffer(name* array, type* buf, u32 count) { cutile_##name##_push_buffer(array, buf, count); }                        \
        maybe_inline void  name##_push_array(name* array, name* other) { cutile_##name##_push_array(array, other); }                                        \
                                                                                                                                                            \
        maybe_inline void  name##_pop(name* array) { cutile_##name##_pop(array); }                                                                          \
        maybe_inline void  name##_remove(name* array, u32 index) { cutile_##name##_remove(array, index); }                                                  \
        maybe_inline void  clear_##name(name* array) { cutile_clear_##name(array); }                                                                        \
        maybe_inline void  clear_##name##_deeply(name* array, void(*dtor)(type*)) { cutile_clear_##name##_deeply(array, dtor); }                            \
                                                                                                                                                            \
        maybe_inline void  reverse_##name##_slice(name* array, u32 offset, u32 count) { cutile_reverse_##name##_slice(array, offset, count); }              \
        maybe_inline void  reverse_##name(name* array) { cutile_reverse_##name(array); }                                                                    \


    #define cutile_generate_named_array_implementation_m(type, name)                                                                                \
        maybe_inline name cutile_create_##name(u32 size, u32 increment, cutile_allocator* allocator)                                                \
        {                                                                                                                                           \
            name res;                                                                                                                               \
            res.data = cutile_allocate_many_T_m(allocator, type, size);                                                                             \
            res.count = 0;                                                                                                                          \
            res.size = size;                                                                                                                        \
            res.increment = increment;                                                                                                              \
            res.allocator = allocator;                                                                                                              \
            return res;                                                                                                                             \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_destroy_##name(name* array)                                                                                        \
        { cutile_deallocate_m(array->allocator, array->data); }                                                                                     \
        maybe_inline void cutile_destroy_##name##_deeply(name* array, void(*dtor)(type*))                                                           \
        {                                                                                                                                           \
            for (u32 i = 0; i < array->count; ++i) dtor(&array->data[i]);                                                                           \
            cutile_deallocate_m(array->allocator, array->data);                                                                                     \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_resize_##name(name* array, u32 new_size)                                                                           \
        {                                                                                                                                           \
            type* new_data =                                                                                                                        \
                (type*)cutile_allocate_m(array->allocator, sizeof(type) * new_size);                                                                \
            if (new_size < array->count)                                                                                                            \
            {                                                                                                                                       \
                for (u32 i = 0; i < new_size; ++i)                                                                                                  \
                {                                                                                                                                   \
                    new_data[i] = array->data[i];                                                                                                   \
                }                                                                                                                                   \
                array->count = new_size;                                                                                                            \
            }                                                                                                                                       \
            else                                                                                                                                    \
            {                                                                                                                                       \
                for (u32 i = 0; i < array->count; ++i)                                                                                              \
                {                                                                                                                                   \
                    new_data[i] = array->data[i];                                                                                                   \
                }                                                                                                                                   \
            }                                                                                                                                       \
            cutile_deallocate_m(array->allocator, array->data);                                                                                     \
            array->data = new_data;                                                                                                                 \
            array->size = new_size;                                                                                                                 \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_##name##_push(name* array, type val)                                                                               \
        {                                                                                                                                           \
            if (array->count >= array->size)                                                                                                        \
            {                                                                                                                                       \
                cutile_resize_##name(array, array->count + array->increment);                                                                       \
            }                                                                                                                                       \
            array->data[array->count] = val;                                                                                                        \
            array->count++;                                                                                                                         \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline type* cutile_##name##_push_empty(name* array)                                                                                  \
        {                                                                                                                                           \
            if (array->count >= array->size)                                                                                                        \
            {                                                                                                                                       \
                cutile_resize_##name(array, array->count + array->increment);                                                                       \
            }                                                                                                                                       \
            return &array->data[array->count++];                                                                                                    \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_##name##_push_repeated(name* array, type val, u32 count)                                                           \
        {                                                                                                                                           \
            if (array->count + count >= array->size)                                                                                                \
            {                                                                                                                                       \
                cutile_resize_##name(array, array->count + count);                                                                                  \
            }                                                                                                                                       \
            for (u32 i = 0; i < count; ++i) array->data[array->count++] = val;                                                                      \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_##name##_push_buffer(name* array, type* buf, u32 count)                                                            \
        {                                                                                                                                           \
            if (array->count + count >= array->size)                                                                                                \
            {                                                                                                                                       \
                cutile_resize_##name(array, array->count + count);                                                                                  \
            }                                                                                                                                       \
            for (u32 i = 0; i < count; ++i) array->data[array->count++] = buf[i];                                                                   \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_##name##_push_array(name* array, name* other) { cutile_##name##_push_buffer(array, other->data, other->count); }   \
                                                                                                                                                    \
        maybe_inline void cutile_##name##_pop(name* array) { array->count--; }                                                                      \
        maybe_inline void cutile_##name##_remove(name* array, u32 index)                                                                            \
        {                                                                                                                                           \
            for (u32 i = index; i < array->count - 1; ++i)                                                                                          \
            {                                                                                                                                       \
                array->data[i] = array->data[i + 1];                                                                                                \
            }                                                                                                                                       \
            array->count -= 1;                                                                                                                      \
        }                                                                                                                                           \
        maybe_inline void cutile_clear_##name(name* array) { array->count = 0; }                                                                    \
        maybe_inline void cutile_clear_##name##_deeply(name* array, void(*dtor)(type*))                                                             \
        {                                                                                                                                           \
            for (u32 i = 0; i < array->count; ++i)                                                                                                  \
            {                                                                                                                                       \
                dtor(&array->data[i]);                                                                                                              \
            }                                                                                                                                       \
            array->count = 0;                                                                                                                       \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_reverse_##name##_slice(name* array, u32 offset, u32 count)                                                         \
        {                                                                                                                                           \
            u32 end = count * 0.5;                                                                                                                  \
            for (u32 i = offset; i < end; ++i)                                                                                                      \
            {                                                                                                                                       \
                type dump = array->data[i];                                                                                                         \
                u32 rhs_i = count - 1 - i;                                                                                                          \
                array->data[i] = array->data[rhs_i];                                                                                                \
                array->data[rhs_i] = dump;                                                                                                          \
            }                                                                                                                                       \
        }                                                                                                                                           \
                                                                                                                                                    \
        maybe_inline void cutile_reverse_##name(name* array) { cutile_reverse_##name##_slice(array, 0, array->count); }                             \

    // Generate some basic array types.
    cutile_generate_array_view_m(s8);
    cutile_generate_array_view_m(u8);
    cutile_generate_array_view_m(s16);
    cutile_generate_array_view_m(u16);
    cutile_generate_array_view_m(s32);
    cutile_generate_array_view_m(u32);
    cutile_generate_array_view_m(s64);
    cutile_generate_array_view_m(u64);
    cutile_generate_array_m(s8);
    cutile_generate_array_m(u8);
    cutile_generate_array_m(s16);
    cutile_generate_array_m(u16);
    cutile_generate_array_m(s32);
    cutile_generate_array_m(u32);
    cutile_generate_array_m(s64);
    cutile_generate_array_m(u64);

    #define CUTILE_ARRAY_H
#endif

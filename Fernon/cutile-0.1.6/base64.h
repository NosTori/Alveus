#ifndef CUTILE_BASE64_H

    #include "cxx.h"
    
    CUTILE_C_API const s8 cutile_base64_table[64];
    CUTILE_C_API const u8 cutile_base64_dtable[255];

    typedef struct cutile_allocator cutile_allocator; // memory.h

    // Does not work for input length of 0 !
    u8* cutile_base64_encode(const u8* in, u64 len, u64* out_len, cutile_allocator* allocator);
    u8* cutile_base64_encode_cstr(const char* cstr, u64* out_len, cutile_allocator* allocator);
    
    u8* cutile_base64_decode(const u8* in, u64 len, u64* out_len, cutile_allocator* allocator);
    u8* cutile_base64_decode_cstr(const char* cstr, u64* out_len, cutile_allocator* allocator);

    // Shortcuts using default allocator.
    #define cutile_base64_encode_(in, len, out_len)   cutile_base64_encode(in, len, out_len, cutile_default_allocator)
    #define cutile_base64_encode_cstr_(cstr, out_len) cutile_base64_encode_cstr(cstr, out_len, cutile_default_allocator)
    #define cutile_base64_decode_(in, len, out_len)   cutile_base64_decode(in, len, out_len, cutile_default_allocator)
    #define cutile_base64_decode_cstr_(cstr, out_len) cutile_base64_decode_cstr(cstr, out_len, cutile_default_allocator)

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define base64_encode(...)      cutile_base64_encode(__VA_ARGS__)
        #define base64_encode_cstr(...) cutile_base64_encode_cstr(__VA_ARGS__)
        #define base64_encode_(...)     cutile_base64_encode_(__VA_ARGS__)

        #define base64_decode(...)      cutile_base64_decode(__VA_ARGS__)
        #define base64_decode_cstr(...) cutile_base64_decode_cstr(__VA_ARGS__)
        #define base64_decode_(...)     cutile_base64_decode_(__VA_ARGS__)
    #endif

    #ifdef CUTILE_IMPLEM

        #include "memory.h"

        const s8 cutile_base64_table[] =
        {
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
            'P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d',
            'e','f','g','h','i','j','k','l','m','n','o','p','q','r','s',
            't','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
        };

        u8* cutile_base64_encode(const u8* in, u64 len, u64* out_len, cutile_allocator* allocator)
        {
            // Calculates the length of the output. Does not work with input length of 0 !
            *out_len = ((len + 2) / 3) * 4;

            u8* out = (u8*)cutile_allocate_m(allocator, *out_len);
            u8* pos = out;
            u8* end = out + *out_len - 1;
            while (len > 2)
            {
                *pos++ = (u8)cutile_base64_table[in[0] >> 2];
                *pos++ = (u8)cutile_base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];    // x03 = b00000011
                *pos++ = (u8)cutile_base64_table[((in[1] & 0x0F) << 2) | (in[2] >> 6)];    // x0F = b00001111
                *pos++ = (u8)cutile_base64_table[in[2] & 0x3F];                            // x3F = b00111111
                len -= 3;
                in += 3;
            }
            if (len == 2)
            {
                *pos++ = (u8)cutile_base64_table[in[0] >> 2];
                *pos++ = (u8)cutile_base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];  // x03 = b00000011
                *pos++ = (u8)cutile_base64_table[(in[1] & 0x0F) << 2];                   // x0F = b00001111
                *pos = '=';        
            }
            else if (len == 1)
            {
                *pos++ = (u8)cutile_base64_table[in[0] >> 2];
                *pos++ = (u8)cutile_base64_table[(in[0] & 0x03) << 4];   // x03 = b00000011
                *pos++ = '=';
                *pos = '=';        
            }

            return out;
        }

        u8* cutile_base64_encode_cstr(const char* cstr, u64* out_len, cutile_allocator* allocator)
        {
            u32 len = 0; while (cstr[len]) { len++; }
            return cutile_base64_encode((u8*)cstr, len, out_len, allocator);
        }
    
        const u8 cutile_base64_dtable[] =
        {
            80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, /* 0 - 15 */
            80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, /* 16 - 31 */
            80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 62, 80, 80, 80, 63, /* 32 - 47 */
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 80, 80, 80, 64, 80, 80, /* 48 - 63 */
            80,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 64 - 79 */
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 80, 80, 80, 80, 80, /* 80 - 96 */
            80, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 87 - 111 */
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 80, 80, 80, 80, 80 /* 112 - 127 */
        }; 

        // Do not use this function if your are unsure input is a valid base64 string.
        u8* cutile_base64_decode(const u8* in, u64 len, u64* out_len, cutile_allocator* allocator)
        {
            // Calculates the length of the output. TODO: This might be wrong and not efficient, check that later.
            *out_len = (len / 4) * 3;
            if (in[len-1] == '=') { (*out_len)--; len--; }
            if (in[len-1] == '=') { (*out_len)--; len--; }
            
            // Generates output.
            u8* out = (u8*)cutile_allocate_m(allocator, *out_len);
            u8* pos = out;
            u8* end = out + *out_len - 1;
            while (len > 3)
            {
                u8 c1 = cutile_base64_dtable[*in];
                ++in;
                u8 c2 = cutile_base64_dtable[*in];
                ++in;
                u8 c3 = cutile_base64_dtable[*in];
                ++in;
                u8 c4 = cutile_base64_dtable[*in];
                ++in;
                
                *pos++ = (c1 << 2) | (c2 >> 4);
                *pos++ = (c2 << 4) | (c3 >> 2);
                *pos++ = (c3 << 6) | c4;
                len -= 4;
            }
            if (len == 3)
            {
                u8 c1 = cutile_base64_dtable[*in];
                u8 c2 = cutile_base64_dtable[in[1]];
                u8 c3 = cutile_base64_dtable[in[2]];
                *pos++ = (c1 << 2) | (c2 >> 4);
                *pos = (c2 << 4) | (c3 >> 2);
            }
            else if (len == 2)
            {
                u8 c1 = cutile_base64_dtable[*in];
                u8 c2 = cutile_base64_dtable[in[1]];
                *pos = (c1 << 2) | (c2 >> 4);
            }

            return out;
        }
    
        u8* cutile_base64_decode_cstr(const char* cstr, u64* out_len, allocator* allocator)
        {
            u32 clen = 0; while (cstr[clen]) clen++;
            return cutile_base64_decode((u8*)cstr, clen, out_len, allocator);
        }
    
    #endif // CUTILE_IMPLEM

    #define CUTILE_BASE64_H

#endif

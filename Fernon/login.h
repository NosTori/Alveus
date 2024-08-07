// Contains stuff related to the login part of the game.

#pragma once

#include "fernon.h"
#include "cutile-0.1.6/str_format.h"
#include "cutile-0.1.6/array.h"

FERNON_NAMESPACE_BEGIN

#define GF_3904_NostaleClientX_LOGIN_IP_ADDRESS_START_ADDRESS  0x000b36b4
#define GF_3904_NostaleClientX_LOGIN_IP_ADDRESS_LENGTH         15
#define GF_3904_NostaleClientX_LOGIN_IP_ADDRESS_VALUE          { 0x37, 0x39, 0x2E, 0x31, 0x31, 0x30, 0x2E, 0x38, 0x34, 0x2E, 0x37, 0x35, 0x00, 0x00, 0x00 }

#define GF_3904_NostaleClient_LOGIN_IP_ADDRESS_START_ADDRESS    0x000a5340
#define GF_3904_NostaleClient_LOGIN_IP_ADDRESS_LENGTH           15
#define GF_3904_NostaleClient_LOGIN_IP_ADDRESS_VALUE            { 0x37, 0x39, 0x2E, 0x31, 0x31, 0x30, 0x2E, 0x38, 0x34, 0x2E, 0x37, 0x35, 0x00, 0x00, 0x00 }

#ifdef GF_3904
    #define NostaleClientX_LOGIN_IP_ADDRESS_START_ADDRESS   GF_3904_NostaleClientX_LOGIN_IP_ADDRESS_START_ADDRESS
    #define NostaleClientX_LOGIN_IP_ADDRESS_LENGTH          GF_3904_NostaleClientX_LOGIN_IP_ADDRESS_LENGTH
    #define NostaleClientX_LOGIN_IP_ADDRESS_VALUE           GF_3904_NostaleClientX_LOGIN_IP_ADDRESS_VALUE

    #define NostaleClient_LOGIN_IP_ADDRESS_START_ADDRESS   GF_3904_NostaleClient_LOGIN_IP_ADDRESS_START_ADDRESS
    #define NostaleClient_LOGIN_IP_ADDRESS_LENGTH          GF_3904_NostaleClient_LOGIN_IP_ADDRESS_LENGTH
    #define NostaleClient_LOGIN_IP_ADDRESS_VALUE           GF_3904_NostaleClient_LOGIN_IP_ADDRESS_VALUE
#endif

////////////////////////////////////////////////////////////////////////////////////////////
// NoS0575:
// Packet sent by the client when attempting to auth in legacy mode: username and password.

#define NoS0575_header "NoS0575 "

struct NoS0575
{
    u8  session_id[8];
    u8  session_id_len;
    u8  username[64];
    u8  username_len;
    u8  password[128];            // Hashed and full upper-case.
    u8  password_len;
    u8  installation_guid[64];    // "NONE" or installed registry key of the client.
    u8  installation_guid_len;
    u8  unknown[16];
    u8  unknown_len;
    u8  client_region;
    u8  client_version[16];
    u8  client_version_len;
    u8  unknown2;
    u8  md5_client_checksum[32]; // MD5 of NostaleClientX.exe concatenated to MD5 of NostaleClient.exe. One MD5 hash is 128 bits (16 bytes), two are 256 bits (32 bytes)
};

maybe_inline b8 is_NoS0575_header(u8* packet, u64 size)
{
    if (size < sizeof(NoS0575_header)) return b8_false;

    return
        packet[0] == 'N' &&
        packet[1] == 'o' &&
        packet[2] == 'S' &&
        packet[3] == '0' &&
        packet[4] == '5' &&
        packet[5] == '7' &&
        packet[6] == '5' &&
        packet[7] == ' ';
}

maybe_inline b8 fill_NoS0575(u8* packet, u64 size, NoS0575* out)
{
    /*
      NoS0575 582180 test EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF NONE 003CA578 00.9.3.3207 0 86270CAB7360342D767FFDE869B60A28
    */

    struct word
    {
        u8* data;
        u64 len;
    } words[9] = {};

    u64 i = sizeof(NoS0575_header) - 1;
    u8  word_count = 0;
    u8* cursor = packet + i;
    u8* current_word = cursor;

    for (u64 i = 0; i < size; ++i)
    {
        if (*cursor == ' ' || *cursor == 0x0B || *cursor == '\n') // Client region and version are separated by 0x0B and not a space character.
        {
            words[word_count++] = {
                current_word,
                cast(u64, cursor - current_word)
            };
            ++cursor;
            current_word = cursor;

            if (word_count == 9) break;
        }
        else
        {
            ++cursor;
        }
    }

    // A valid NoS0575 packet has 9 words after the header.
    if (word_count == 9)
    {
        // Parse session id.
        if (words[0].len > 8) return b8_false;
        for (u32 i = 0; i < words[0].len; ++i)
        {
            out->session_id[i] = words[0].data[i];
        }
        out->session_id_len = words[0].len;

        // Parse username.
        if (words[1].len > 64) return b8_false;
        for (u32 i = 0; i < words[1].len; ++i)
        {
            out->username[i] = words[1].data[i];
        }
        out->username_len = words[1].len;

        // Parse password.
        if (words[2].len != 128) return b8_false;
        for (u32 i = 0; i < 128; ++i)
        {
            out->password[i] = words[2].data[i];
        }
        out->password_len = words[2].len;

        // Parse installation guid.
        if (words[3].len > 64) return b8_false;
        for (u32 i = 0; i < words[3].len; ++i)
        {
            out->installation_guid[i] = words[3].data[i];
        }
        out->installation_guid_len = words[3].len;

        // Parse unknown.
        if (words[4].len > 16) return b8_false;
        for (u32 i = 0; i < words[4].len; ++i)
        {
            out->unknown[i] = words[4].data[i];
        }
        out->unknown_len = words[4].len;

        // Parse client region.
        if (words[5].len > 1) return b8_false;
        out->client_region = words[5].data[0] - '0';

        // Parse client version.
        if (words[6].len > 16) return b8_false;
        for (u32 i = 0; i < words[6].len; ++i)
        {
            out->client_version[i] = words[6].data[i];
        }
        out->client_version_len = words[6].len;

        // Parse unknown2.
        if (words[7].len > 1) return b8_false;
        out->unknown2 = words[7].data[0] - '0';

        // Parse md5 checksum.
        if (words[8].len != 32) return b8_false;
        for (u32 i = 0; i < 32; ++i)
        {
            out->md5_client_checksum[i] = words[8].data[i];
        }

        return b8_true;
    }

    return b8_false;
}

////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////
// NoS0577:
// Packet sent by the client when attempting to auth after launching the game with GF launcher; using an auth token generated from the GF launcher.

struct NoS0577
{
    array_view(u8) auth_token;
    array_view(u8) installation_guid;
    array_view(u8) unknown;
    u8             client_region;
    array_view(u8) client_version;
    u8             unknown2;
    array_view(u8) md5_client_checksum; // MD5 of NostaleClientX.exe concatenated to MD5 of NostaleClient.exe
};

////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////
// failc:
// "failc" packet is sent by the server when an error occurred when the client attempts to connect.

enum failc_reason
{
    FAILC_OUTDATED_CLIENT = 1,
    FAILC_UNHANDLED_ERROR = 2,
    FAILC_MAINTENANCE = 3,
    FAILC_ALREADY_CONNECTED = 4,
    FAILC_WRONG_CREDS = 5,
    FAILC_CANT_CONNECT = 6,
    FAILC_BANNED = 7,
    FAILC_WRONG_COUNTRY = 8,
    FAILC_WRONG_CAPS = 9
};

struct failc
{
    u8 data[7];
    u8 terminator;
};

maybe_inline failc generate_failc_packet(failc_reason reason)
{
    failc result;
    result.data[0] = 'f';
    result.data[1] = 'a';
    result.data[2] = 'i';
    result.data[3] = 'l';
    result.data[4] = 'c';
    result.data[5] = ' ';
    result.data[6] = reason + '0';
    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////
// NsTeST:
// World servers list packet sent by the login server to the login client.

struct NsTeST_world_character_count
{
    u32 world_group_id;
    u8  character_count;
};
cutile_generate_array_view_m(NsTeST_world_character_count);

struct NsTeST_sub
{
    u8      world_host[64];
    u8      world_host_len;
    u16     world_port;

    u32     color;

    u32     world_count;
    u32     world_group_id;

    u8      world_group_name[64];
    u8      world_group_name_len;
};
cutile_generate_array_m(NsTeST_sub);
cutile_generate_array_view_m(NsTeST_sub);

struct NsTeST
{
    u8                      region;

    u8                      username[64];
    u8                      username_len;

    s32                     unknown;

    array_view(NsTeST_world_character_count) character_counts;

    u8                      session_id[8];
    u8                      session_id_len;

    array_view(NsTeST_sub)  subs;
};

maybe_inline void decode_login_packet(u8* bytes, u64 size);
maybe_inline string generate_NsTeST(NsTeST* arg, cutile_allocator* allocator, b8 gf_auth = b8_false)
{
    string result;
    if (gf_auth)
    {
        result = format_str("NsTeST  % % %", 
                            arg->region,
                            format_memory_to_str(arg->username, arg->username_len),
                            arg->unknown);
    }
    else
    {
        result = format_str("NsTeST  % %", 
                            arg->region,
                            format_memory_to_str(arg->username, arg->username_len));
    }

    // for (u32 i = 0; i < arg->character_counts.count; ++i)
    // {
    //     const NsTeST_world_character_count* sub = &arg->character_counts.data[i];
    //     format_str(&result, " % %",
    //                sub->world_id, sub->character_count);
    // }

    format_str(&result, " %", format_memory_to_str(arg->session_id, arg->session_id_len));

    for (u32 i = 0; i < arg->subs.count; ++i)
    {
        const NsTeST_sub* sub = &arg->subs.data[i];
        format_str(&result, " %:%:%:%.%.%",
                   format_memory_to_str(sub->world_host, sub->world_host_len),
                   sub->world_port,
                   sub->color,
                   sub->world_count,
                   sub->world_group_id,
                   format_memory_to_str(sub->world_group_name, sub->world_group_name_len)
                   );
    }

    // Dummy world channel info as a packet ender.
    str_push_back_cstr(&result, " -1:-1:-1:10000.10000.1"/*might be 4 when using GF auth token*/);

    return result;
}

////////////////////////////////////////////////////////////////////////////////////////////

#define FERNON_DEFAULT_EU_LOGIN_PORT 4000

maybe_inline void decode_login_packet(u8* bytes, u64 size)
{
    for (u64 i = 0; i < size; ++i)
    {
        u8 c = bytes[i];
        if (c > 14) c -= 15;
        else c = 256 - (15 - c);
        c ^= 195;
        bytes[i] = c;
    }
}

maybe_inline void encode_login_packet(u8* bytes, u64 size)
{
    for (u64 i = 0; i < size - 1; ++i)
    {
        bytes[i] += 15;
    }
    bytes[size - 1] = 25;
}

FERNON_NAMESPACE_END

#define CUTILE_IMPLEM
#if WINDOWS
    #define WIN32_LEAN_AND_MEAN
#endif
#include "../network.h"
#include "../test.h"
#include "../print.h"

int main()
{
    cutile_test_begin_m();

    #if WINDOWS
        WSADATA wsa_data;
        int wsa_result;
        wsa_result = WSAStartup(MAKEWORD(2,2), &wsa_data);
        cutile_test_require_m(!wsa_result);
    #endif

    net_socket sock;
    net_error err = open_net_socket(net_socket_stream, cutile_net_af_ipv4, net_tcp_protocol, &sock);
    cutile_test_assert_m(err == net_no_error);
    if (err != net_no_error)
    {
        println_cstr(cutile_get_net_error_msg(err));
    }

    cutile_test_assert_m(cutile_is_ipv4_cstr_valid("127.0.0.1"));

    ipv4_endpoint ipv4 = cutile_create_ipv4_endpoint("127.0.0.1", 34783);
    #ifdef CUTILE_CPP
        err = cutile_bind_net_socket(&sock, &ipv4);
    #else
        err = cutile_bind_net_socket(&sock, (cutile_net_endpoint*)&ipv4);
    #endif
    cutile_test_assert_m(err == net_no_error);
    if (err)
    {
        println_cstr(cutile_get_net_error_msg(err));
    }

    err = close_net_socket(&sock);
    cutile_test_assert_m(err == net_no_error);

    #if WINDOWS
        WSACleanup();
    #endif

    cutile_test_end_m();
}

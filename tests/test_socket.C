
#include <iostream>
#include <cybermon/socket.h>
#include <assert.h>

int main(int argc, char** argv)
{

    tcpip::ip4_address a1("1.2.3.4");

    std::string out;
    a1.to_string(out);

    assert(out == "1.2.3.4");

    tcpip::ip4_address a2 = a1 & 24;
    a2.to_string(out);
    assert(out == "1.2.3.0");

    tcpip::ip4_address a3("249.89.32.127");

    a2 = a3 & 8;
    a2.to_string(out);
    assert(out == "249.0.0.0");

    a2 = a3 & 11;
    a2.to_string(out);
    assert(out == "249.64.0.0");

    a2 = a3 & 20;
    a2.to_string(out);
    assert(out == "249.89.32.0");

    tcpip::ip6_address a4("aa:bb:cc:dd:ee:ff:67:91");

}



#include "address_map.h"
#include <cybermon/socket.h>
#include <string>
#include <assert.h>

class bunchy {
public:
    bunchy(const std::string& f, const std::string& n) : fruit(f), name(n) {}
    bunchy() {}
    std::string fruit;
    std::string name;
};

void test4() {

    std::cout << "--------------------" << std::endl;
    std::cout << "---- IPv4" << std::endl;
    std::cout << "--------------------" << std::endl;

    address_map<tcpip::ip4_address, bunchy> map;

    map.insert(tcpip::ip4_address("1.2.0.0"), 16, bunchy("lemon", "bill"));
    map.insert(tcpip::ip4_address("1.0.0.0"), 8, bunchy("apple", "fred"));

    const bunchy* b;

    bool hit = map.get(tcpip::ip4_address("1.2.3.4"), b);
    assert(hit == true);
    assert(b->fruit == "lemon");
    assert(b->name == "bill");

    hit = map.get(tcpip::ip4_address("1.2.3.5"), b);
    assert(hit == true);
    assert(b->fruit == "lemon");
    assert(b->name == "bill");

    hit = map.get(tcpip::ip4_address("1.1.3.4"), b);
    assert(hit == true);
    assert(b->fruit == "apple");
    assert(b->name == "fred");
    
    hit = map.get(tcpip::ip4_address("1.0.8.1"), b);
    assert(hit == true);
    assert(b->fruit == "apple");
    assert(b->name == "fred");

    map.remove(tcpip::ip4_address("1.0.0.0"), 8);

    hit = map.get(tcpip::ip4_address("1.1.3.4"), b);
    assert(hit == false);
    
    hit = map.get(tcpip::ip4_address("15.0.8.1"), b);
    assert(hit == false);

    std::cout << "Tests passed." << std::endl;
    
}

void test6() {

    std::cout << "--------------------" << std::endl;
    std::cout << "---- IPv6" << std::endl;
    std::cout << "--------------------" << std::endl;

    address_map<tcpip::ip6_address, bunchy> map;

    map.insert(tcpip::ip6_address("a1ff:ee:cc:dd::0"), 64,
	       bunchy("lemon", "bill"));
    map.insert(tcpip::ip6_address("a1ff:ee::0"), 32,
	       bunchy("apple", "fred"));

    const bunchy* b;

    bool hit = map.get(tcpip::ip6_address("a1ff:ee:cc:dd::1"), b);
    assert(hit == true);
    assert(b->fruit == "lemon");
    assert(b->name == "bill");

    hit = map.get(tcpip::ip6_address("a1ff:ee:cc:dd::3"), b);
    assert(hit == true);
    assert(b->fruit == "lemon");
    assert(b->name == "bill");

    hit = map.get(tcpip::ip6_address("a1ff:ee:aa:dd::3"), b);
    assert(hit == true);
    assert(b->fruit == "apple");
    assert(b->name == "fred");
    
    hit = map.get(tcpip::ip6_address("a1ff:ee:aa:dd::4"), b);
    assert(hit == true);
    assert(b->fruit == "apple");
    assert(b->name == "fred");

    map.remove(tcpip::ip6_address("a1ff:ee::0"), 32);

    hit = map.get(tcpip::ip6_address("a1ff:ee:aa:dd::4"), b);
    assert(hit == false);

    hit = map.get(tcpip::ip6_address("a1ee:ee:aa:dd::4"), b);
    assert(hit == false);

    std::cout << "Tests passed." << std::endl;
    
}

int main() {

    test4();
    test6();

}



#include "socket.h"

#include "address.h"

#include <iomanip>

using namespace analyser;


// Describe the address in human-readable on an output-stream.
void address::describe(std::ostream& out)
{

    if (proto == NO_PROTOCOL) {
	out << "No protocol";
	return;
    }

    if (proto == IP4) {
	tcpip::ip4_address a;
	if (addr.size() != 4)
	    throw std::runtime_error("Invalid address data for IPv4");
	a.addr.assign(addr.begin(), addr.end());
	out << "IPv4 " << a;
	return;
    }

    if (proto == TCP || proto == UDP) {
	if (addr.size() != 2)
	    throw std::runtime_error("Invalid address data for port");
	unsigned int p = (addr[0] << 8) + addr[1];
	if (proto == TCP)
	    out << "TCP ";
	else
	    out << "UDP ";
	out << std::dec << std::setw(0) << p;
	return;
    }

    if (proto == ICMP) {
	out << "ICMP";
	return;
    }

    out << "Not describable";

}


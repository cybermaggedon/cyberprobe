
#include <cyberprobe/network/socket.h>
#include <cyberprobe/protocol/address.h>
#include <cyberprobe/util/hardware_addr_utils.h>

#include <iomanip>
#include <arpa/inet.h>

using namespace cyberprobe::protocol;

void address::get(std::string& cls, std::string& address) const
{
    if (layer == ROOT) {
	cls = "root"; address = "";
	return;
    }

    if (proto == NO_PROTOCOL) {
	cls = "no_protocol"; address = "";
	return;
    }

    if (proto == IP4) {
	tcpip::ip4_address a;
	if (addr.size() != 4)
	    throw std::runtime_error("Invalid address data for IPv4");
	a.addr.assign(addr.begin(), addr.end());
	cls = "ipv4"; 
	a.to_string(address);
	return;
    }

    if (proto == IP6) {
	tcpip::ip6_address a;
	if (addr.size() != 16)
	    throw std::runtime_error("Invalid address data for IPv6");
	a.addr.assign(addr.begin(), addr.end());
	cls = "ipv6";
	a.to_string(address);
	return;
    }

    if (proto == TCP || proto == UDP) {
	if (addr.size() != 2)
	    throw std::runtime_error("Invalid address data for port");
	unsigned int p = (addr[0] << 8) + addr[1];
	if (proto == TCP)
	    cls = "tcp";
	else
	    cls = "udp";
	std::ostringstream buf;
	buf << std::dec << p;
	address = buf.str();
	return;
    }

    if (proto == ICMP) {
	cls = "icmp"; address = "";
	return;
    }

    if (proto == IMAP) {
        cls = "imap"; address = "";
        return;
    }

    if (proto == IMAP_SSL) {
        cls = "imap_ssl"; address = "";
        return;
    }

    if (proto == POP3) {
        cls = "pop3"; address = "";
        return;
    }

    if (proto == POP3_SSL) {
        cls = "pop3_ssl"; address = "";
        return;
    }

    if (proto == SIP) {
        cls = "sip"; address = "";
        return;
    }

    if (proto == SIP_SSL) {
        cls = "sip_ssl"; address = "";
        return;
    }

    if (proto == SMTP_AUTH) {
        cls = "smtp_auth"; address = "";
        return;
    }

    if (proto == HTTP) {
	cls = "http"; address = "";
	return;
    }

    if (proto == DNS) {
        cls = "dns"; address = "";
        return;
    }

    if (proto == SMTP) {
	cls = "smtp"; address = "";
	return;
    }

    if (proto == FTP) {
	cls = "ftp"; address = "";
	return;
    }
    
    if (proto == NTP) {
	cls = "ntp"; address = "";
	return;
    }

    if (proto == GRE) {
	cls = "gre"; address = "";
	return;
    }

    if (proto == ESP) {
        cls = "esp"; address = "";
        if (addr.size() == 4)
            {
                const uint32_t* spi = reinterpret_cast<const uint32_t*>(&addr[0]);
                std::ostringstream buf;
                buf << std::dec << ntohl(*spi);
                address = buf.str();
            } else if (addr.size() == 0)
            {
                address = "";
            } else
            {
                throw std::runtime_error("Invalid address data for esp spi");
            }
  	return;
    }

    if (proto == WLAN) {
        cls = "802.11";
        address = util::hw_addr_utils::to_string(&addr[0]);
        return;
    }

    if (proto == TLS) {
 	cls = "tls";
 	address = "";
 	return;
    }
     

    if (proto == UNRECOGNISED) {
	cls = "unrecognised"; address = "";
	return;
    }

}

// Describe the address in human-readable on an output-stream.
void address::describe(std::ostream& out) const
{

    if (layer == ROOT) {
	return;
    }

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

    if (proto == IP6) {
	tcpip::ip6_address a;
	if (addr.size() != 16)
	    throw std::runtime_error("Invalid address data for IPv6");
	a.addr.assign(addr.begin(), addr.end());
	out << "IPv6 " << a;
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

    if (proto == HTTP) {
	out << "HTTP";
	return;
    }

    if (proto == DNS) {
        out << "DNS";
        return;
    }

    if (proto == SMTP) {
	out << "SMTP";
	return;
    }

    if (proto == FTP) {
	out << "FTP";
	return;
    }
    
    if (proto == NTP) {
	out << "NTP";
	return;
    }

    if (proto == UNRECOGNISED) {
	out << "Unrecognised";
	return;
    }

    out << "Not describable";

}


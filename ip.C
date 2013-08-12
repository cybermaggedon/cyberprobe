
#include "ip.h"
#include "tcp.h"
#include "udp.h"

#include "analyser.h"

using namespace analyser;

void ip::process_ip4(engine& eng, context_ptr c, 
		     const pdu_iter& s, const pdu_iter& e)
{

    if ((e - s) < 20) throw exception("Packet too small for IPv4");

    unsigned int length = (s[2] << 8) + s[3];

    if ((e - s) != length) throw exception("IP packet doesn't agree with its "
					   "length field");

    // Stuff from the IP header.
    unsigned short ihl = s[0] & 0x0f;
    unsigned short id = s[4] << 8 + s[5];
    unsigned short flags = s[6] >> 5;
    unsigned short frag_offset = (s[6] & 0x1f) + s[7];
    unsigned short protocol = s[9];
    unsigned short cksum = s[10] << 8 + s[11];

    if (flags & 4)
	throw exception("IP fragmentation not implemented");

    if (ihl < 5) throw exception("IP packet IHL is invalid");

    unsigned short header_length = ihl * 4;
    if ((e - s) < header_length) throw exception("IP packet IHL is invalid");

    // Calculate checksum.
    unsigned short checked = calculate_cksum(s, s + header_length);
    if (checked != 0)
	throw exception("IP packet has invalid checksum");

    // Addresses.
    tcpip::ip4_address src, dest;
    src.addr.assign(s + 12, s + 16);
    dest.addr.assign(s + 16, s + 20);

    flow f(src, dest);
    
    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new ip4_context(f, c));
	c->add_child(f, fc);
    }

    // Process payloads.
    if (protocol == 6)

	// TCP
	tcp::process(eng, fc, s + header_length, e);

    else if (protocol == 17)
	
	// UDP
	udp::process(eng, fc, s + header_length, e);

    else

	throw std::runtime_error("IP protocol not handled.");


//    if (protocol == 17) return;

//    std::cerr << "Protocol: " << protocol << std::endl;

}

void ip::process_ip6(engine& eng, context_ptr c, 
		     const pdu_iter& s, const pdu_iter& e)
{
    throw exception("IPv6 processing not implemented.");
}

unsigned short ip::calculate_cksum(const pdu_iter& s, const pdu_iter& e)
{
    
    pdu_iter ptr = s;

    unsigned long sum = 0;

    // Handle 2-bytes at a time.
    while ((e - ptr) > 1) {
	sum += (ptr[0] << 8) + ptr[1];
	if (sum & 0x80000000)
	    sum = (sum & 0xffff) + (sum >> 16);
	ptr += 2;
    }

    // If a remaining byte, handle that.
    if ((e - ptr) != 0)
	sum += ptr[0];

    while (sum >> 16) {
	sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;

}


void ip::process(engine& eng, context_ptr c, 
		 const pdu_iter& s, const pdu_iter& e)
{

  // Packet too small for the IP check, then do nothing.
  if ((e - s) < 1)
    throw exception("Empty packet");

  if ((*s & 0xf0) == 0x40)
      process_ip4(eng, c, s, e);
  else if ((*s & 0xf0) == 0x60)
      process_ip6(eng, c, s, e);
  else
      throw exception("Expecting IP, but isn't IPv4 or IPv6");

}

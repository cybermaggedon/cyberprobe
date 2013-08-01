
#include <algorithm>
#include <pcap.h>

#include "delivery.h"

// This method studies the packet data, and PCAP datalink attribute, and:
// - Returns the IP version (4 or 6).
// - Alters the start iterator to point at the start of the IP packet.
void delivery::identify_link(const_iterator& start,
			     const_iterator& end,
			     int datalink,
			     int& ipv)
{

    if (datalink == DLT_EN10MB) {

	// Ethernet case

	// Not long enough for Ethernet frame, bail.
	if ((end - start) < 14)
	    throw std::runtime_error("Too small for Ethernet");

	// Get IP version from Ethertype
	if (start[12] == 0x08 && start[13] == 0) ipv = 4;
	else if (start[12] == 0x86 && start[13] == 0xdd) ipv = 6;
	else
	    throw std::runtime_error("Not IP protocol");

	// Skip the Ethernet frame.
	start += 14;

	return;

    } else if (datalink == DLT_LINUX_SLL) {

	// Linux "cooked" case

	// Cooked header length.
	if ((end - start) < 16) 
	    throw std::runtime_error("Too small for cooked");

	// Get IP version from Ethertype
	if (start[14] == 0x08 && start[15] == 0) ipv = 4;
	if (start[14] == 0x86 && start[15] == 0xdd) ipv = 6;

	// Skip cooked header
	start += 16;

	return;

    } else if (datalink == DLT_RAW) {

	// Raw IP packet case.

	// Not long enough for check, bail.  In other bits of the code,
	// there's a check for the real IP header length.
	if ((end - start) < 1) return;
	
	// IPv4 or 6 test.
	if ((start[0] & 0xf0) == 0x40)
	    ipv = 4;
	else
	    ipv = 6;

    } else {

	// Don't know what to do.  It's not one of the link types that
	// I'm expecting.
	throw std::runtime_error("Don't know about that link type.");

    }

}

// Study an IPv4 packet, and work out if the addresses match a target
// address.  Returns true for a match, and 'liid' returns the target LIID.
bool delivery::ipv4_match(const_iterator& start,
			  const_iterator& end,
			  std::string& liid,
			  tcpip::ip4_address& hit)
{

    // Too small to be an IP packet?
    if (end - start < 20) return false;
    
    // Get the source address
    tcpip::ip4_address saddr, daddr;
    saddr.addr.assign(start + 12, start + 16);
    daddr.addr.assign(start + 16, start + 20);

    // Get the target map lock.
    lock.lock();

    // Find a match against the source or destination IP address.
    std::map<tcpip::ip4_address, std::string>::const_iterator it;
    it = targets.find(saddr);
    if (it == targets.end())
	it = targets.find(daddr);
	
    // If no match, then ignore the packet.
    if (it == targets.end()) {
	lock.unlock();
	return false;
    }
	
    // At this point 'it' definitely points at a target entry.
    // Get LIID and address information.
    hit = it->first;
    liid = it->second;

    lock.unlock();

    return true;

}

// Study an IPv6 packet, and work out if the addresses match a target
// address.  Returns true for a match, and 'liid' returns the target LIID.
bool delivery::ipv6_match(const_iterator& start,
			  const_iterator& end,
			  std::string& liid,
			  tcpip::ip6_address& hit)
{

    // Too small to be an IPv6 packet?
    if (end - start < 40) return false;

    // Get the source,dest address
    tcpip::ip6_address saddr, daddr;
    saddr.addr.assign(start + 8, start + 24);
    daddr.addr.assign(start + 24, start + 40);

    // Get the target map lock.
    lock.lock();

    // Find a match against the source or destination IP address.
    std::map<tcpip::ip6_address, std::string>::const_iterator it;
    it = targets6.find(saddr);
    if (it == targets6.end())
	it = targets6.find(daddr);

    // If no match, then ignore the packet.
    if (it == targets6.end()) {
	lock.unlock();
	return false;
    }
    // At this point 'it' definitely points at a target entry.
    // Get LIID and address information.
    hit = it->first;
    liid = it->second;

    lock.unlock();

    return true;

}

// The 'main' packet handling method.  This is what the caller calls when
// they have a packet.  datalink = the PCAP datalink value.
void delivery::deliver(const std::vector<unsigned char>& packet, int datalink)
{

    // Iterators, initially point at the start and end of the packet.
    std::vector<unsigned char>::const_iterator start = packet.begin();
    std::vector<unsigned char>::const_iterator end = packet.end();
    int ipv;

    // Start by handling the link layer.
    try {
	identify_link(start, end, datalink, ipv);
    } catch (...) {
	// Silently ignore exceptions.
	return;
    }

    // If a target match, the LIID will go here.
    std::string liid;

    if (ipv == 4) {

	// IPv4 case

	tcpip::ip4_address hit;

	// Match the IP addresses.
	bool match = ipv4_match(start, end, liid, hit);

	// No target match?
	if (!match) return;

	// Get the target map lock.
	lock.lock();

	// Now invoke destinations, and send packet to destinations.
	for(std::list<sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    (*it)->deliver(liid, start, end, hit);
	}
	
	// Unlock, we're done.
	lock.unlock();

    }

    if (ipv == 6) {

	// IPv6 case

	tcpip::ip6_address hit;

	// Match the IP addresses.
	bool match = ipv6_match(start, end, liid, hit);

	// No target match?
	if (!match) return;

	// Get the target map lock.
	lock.lock();

	// Now invoke destinations, and send packet to destinations.
	for(std::list<sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    (*it)->deliver(liid, start, end, hit);
	}
	
	// Unlock, we're done.
	lock.unlock();

    }

}


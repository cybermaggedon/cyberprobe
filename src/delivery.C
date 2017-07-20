
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
	if (start[12] == 0x08 && start[13] == 0) {
	    ipv = 4;		// IPv4
	    start += 14;	// Skip the Ethernet frame.
	    return;
	} else if (start[12] == 0x86 && start[13] == 0xdd) {
	    ipv = 6;		// IPv6
	    start += 14;	// Skip the Ethernet frame.
	    return;
	}

	// 802.1q (VLAN)
	if (start[12] == 0x81 && start[13] == 0x00) {

	    if ((end - start) < 18)
		throw std::runtime_error("Too small for 802.1q");

	    if (start[16] == 0x08 && start[17] == 0) {
		ipv = 4;		// IPv4
		start += 18;		// Skip the Ethernet frame.
		return;
	    }

	    if (start[16] == 0x86 && start[17] == 0xdd) {
		ipv = 6;		// IPv6
		start += 18;		// Skip the Ethernet frame.
		return;
	    }

	}

	throw std::runtime_error("Not IP protocol");

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

    // FIXME: What if it matches on more than one address?!
    // FIXME: Should be tagged with more than one LIID?

    // Too small to be an IP packet?
    if (end - start < 20) return false;
    
    // Get the source address
    tcpip::ip4_address saddr, daddr;
    saddr.addr.assign(start + 12, start + 16);
    daddr.addr.assign(start + 16, start + 20);

    // Get the target map lock.
    targets_lock.lock();

    // Search mask map
    typedef std::map<tcpip::ip4_address, std::string> addr_map;
    std::map<int, addr_map>::const_iterator it;
    for(it = targets.begin(); it != targets.end(); it++) {

	// mask
	unsigned int mask = it->first;

	// FIXME: Apply the mask

	// Find a match against the source or destination IP address.
	std::map<tcpip::ip4_address, std::string>::const_iterator it2;
	
	it2 = it->second.find(saddr & mask);
	if (it2 == it->second.end())
	    it2 = it->second.find(daddr & mask);
	
	// If match, then return info.
	if (it2 != it->second.end()) {
	    hit = it2->first;
	    liid = it2->second;
	    targets_lock.unlock();
	    return true;
	}

    }

    // No match.
    targets_lock.unlock();
    return false;

}

// Study an IPv6 packet, and work out if the addresses match a target
// address.  Returns true for a match, and 'liid' returns the target LIID.
bool delivery::ipv6_match(const_iterator& start,
			  const_iterator& end,
			  std::string& liid,
			  tcpip::ip6_address& hit)
{

    // FIXME: What if it matches on more than one address?!
    // FIXME: Should be tagged with more than one LIID? 

    // Too small to be an IPv6 packet?
    if (end - start < 40) return false;

    // Get the source,dest address
    tcpip::ip6_address saddr, daddr;
    saddr.addr.assign(start + 8, start + 24);
    daddr.addr.assign(start + 24, start + 40);

    // Get the target map lock.
    targets_lock.lock();

    // Search mask map
    typedef std::map<tcpip::ip6_address, std::string> addr_map;
    std::map<int, addr_map>::iterator it;
    for(it = targets6.begin(); it != targets6.end(); it++) {

	// Find a match against the source or destination IP address.
	std::map<tcpip::ip6_address, std::string>::iterator it2;

	// mask
	unsigned int mask = it->first;

	// Find a match against the source or destination IP address.
	it2 = it->second.find(saddr & mask);
	if (it2 == it->second.end())
	    it2 = it->second.find(daddr & mask);
	
	// If match, then return info.
	if (it2 != it->second.end()) {
	    hit = it2->first;
	    liid = it2->second;
	    targets_lock.unlock();
	    return true;
	}

    }

    // No match.
    targets_lock.unlock();
    return false;

}

// The 'main' packet handling method.  This is what the caller calls when
// they have a packet.  datalink = the PCAP datalink value.
void delivery::receive_packet(const std::vector<unsigned char>& packet, 
			      int datalink)
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

	// Get the senders list lock.
	senders_lock.lock();

	// Now invoke destinations, and send packet to destinations.
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->deliver(liid, start, end);
	}
	
	// Unlock, we're done.
	senders_lock.unlock();

    }

    if (ipv == 6) {

	// IPv6 case

	tcpip::ip6_address hit;

	// Match the IP addresses.
	bool match = ipv6_match(start, end, liid, hit);

	// No target match?
	if (!match) return;

	// Get the senders list lock.
	senders_lock.lock();

	// Now invoke destinations, and send packet to destinations.
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->deliver(liid, start, end);
	}
	
	// Unlock, we're done.
	senders_lock.unlock();

    }

}

// Modifies interface capture
void delivery::add_interface(const std::string& iface,
			     const std::string& filter,
			     float delay) 
{
    
    interfaces_lock.lock();
    
    intf i;
    i.interface = iface;
    i.filter = filter;
    i.delay = delay;
    capture_dev* c;

    if (interfaces.find(i) != interfaces.end()) {
	interfaces[i]->stop();
	interfaces.erase(i);
    }

    try {

	c = new capture_dev(iface, delay, *this);
	if (filter != "")
	    c->add_filter(filter);

	c->start();
	
	interfaces[i] = c;

    } catch (std::exception& e) {
	interfaces_lock.unlock();
	throw;
    }

    interfaces_lock.unlock();

}

// Modifies interface capture
void delivery::remove_interface(const std::string& iface,
				const std::string& filter,
				float delay)
{

    interfaces_lock.lock();

    intf i;
    i.interface = iface;
    i.filter = filter;
    i.delay = delay;

    if (interfaces.find(i) != interfaces.end()) {
	interfaces[i]->stop();
	interfaces.erase(i);
    }

    interfaces_lock.unlock();

}

void delivery::get_interfaces(std::list<interface_info>& ii)
{

    ii.clear();
    
    interfaces_lock.lock();
    
    for(std::map<intf,capture_dev*>::iterator it = interfaces.begin();
	it != interfaces.end();
	it++) {
	interface_info inf;
	inf.interface = it->first.interface;
	inf.filter = it->first.filter;
	inf.delay = it->first.delay;
	ii.push_back(inf);
    }
    
    interfaces_lock.unlock();

}

// Modifies the target map to include a mapping from address to target.
void delivery::add_target(const tcpip::address& addr, 
			  unsigned int mask,
			  const std::string& liid) 
{

    targets_lock.lock();

    if (addr.universe == addr.ipv4) {
	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(addr);
	targets[mask][a & mask] = liid;
    } else {
	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(addr);
	targets6[mask][a & mask] = liid;
    }

    // Tell all senders, target up.
    senders_lock.lock();
    for(std::map<ep,sender*>::iterator it = senders.begin();
	it != senders.end();
	it++) {
	it->second->target_up(liid, addr);
    }
    senders_lock.unlock();

    targets_lock.unlock();

}

// Removes a target mapping.
void delivery::remove_target(const tcpip::address& addr, unsigned int mask) 
{
    
    targets_lock.lock();

    std::string liid;

    if (addr.universe == addr.ipv4) {
	
	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(addr);

	if (targets.find(mask) == targets.end()) {
	    // Mask not in the target map.  Silenty ignore.
	    targets_lock.unlock();
	    return;
	}

	if (targets[mask].find(a) == targets[mask].end()) {
	    // Target not in the target map.  Silenty ignore.
	    targets_lock.unlock();
	    return;
	}

	// Tell all senders, target down.
	senders_lock.lock();
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->target_down(targets[mask][a]);
	}
	senders_lock.unlock();

	targets[mask].erase(a);

    } else {

	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(addr);

	if (targets6.find(mask) == targets6.end()) {
	    // Mask not in the target map.  Silenty ignore.
	    targets_lock.unlock();
	    return;
	}

	if (targets6[mask].find(a) == targets6[mask].end()) {
	    // Target not in the target map.  Silenty ignore.
	    targets_lock.unlock();
	    return;
	}

	// Tell all senders, target down.
	senders_lock.lock();
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->target_down(targets6[mask][a]);
	}

	senders_lock.unlock();

	targets6[mask].erase(a);

    }

    targets_lock.unlock();

}

// Fetch current target list.
void delivery::get_targets(std::map<int, 
			   std::map<tcpip::ip4_address, std::string> >& t4,
			   std::map<int,
			   std::map<tcpip::ip6_address, std::string> >& t6) 
{
    t4 = targets;
    t6 = targets6;
}

// Adds an endpoint
void delivery::add_endpoint(const std::string& host, unsigned int port,
			    const std::string& type,
			    const std::string& transport,
			    const std::map<std::string, std::string>& params)
{

    senders_lock.lock();
    
    ep e(host, port, type, transport, params);

    sender* s;

    if (senders.find(e) != senders.end()) {
	senders[e]->stop();
	senders.erase(e);
    }

    if (type == "nhis1.1") {
	s = new nhis11_sender(host, port, transport, params, *this);
    } else if (type == "etsi") {
	s = new etsi_li_sender(host, port, transport, params, *this);
    } else {
	senders_lock.unlock();
	throw std::runtime_error("Endpoint type not known.");
    }

    s->start();
    senders[e] = s;

    senders_lock.unlock();
}

// Removes an endpoint
void delivery::remove_endpoint(const std::string& host, unsigned int port,
			       const std::string& type,
			       const std::string& transport,
			       const std::map<std::string, std::string>& params)
{

    senders_lock.lock();

    ep e(host, port, type, transport, params);

    if (senders.find(e) != senders.end()) {
	senders[e]->stop();
	senders.erase(e);
    }

    senders_lock.unlock();

}

// Fetch current target list.
void delivery::get_endpoints(std::list<sender_info>& info) 
{

    senders_lock.lock();

    info.clear();
    for(std::map<ep,sender*>::iterator it = senders.begin();
	it != senders.end();
	it++) {
	sender_info inf;
	it->second->get_info(inf);
	info.push_back(inf);
    }

    senders_lock.unlock();

}

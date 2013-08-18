
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

    // Find a match against the source or destination IP address.
    std::map<tcpip::ip4_address, std::string>::const_iterator it;
    it = targets.find(saddr);
    if (it == targets.end())
	it = targets.find(daddr);
	
    // If no match, then ignore the packet.
    if (it == targets.end()) {
	targets_lock.unlock();
	return false;
    }
	
    // At this point 'it' definitely points at a target entry.
    // Get LIID and address information.
    hit = it->first;
    liid = it->second;

    targets_lock.unlock();

    return true;

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

    // Find a match against the source or destination IP address.
    std::map<tcpip::ip6_address, std::string>::const_iterator it;
    it = targets6.find(saddr);
    if (it == targets6.end())
	it = targets6.find(daddr);

    // If no match, then ignore the packet.
    if (it == targets6.end()) {
	targets_lock.unlock();
	return false;
    }
    // At this point 'it' definitely points at a target entry.
    // Get LIID and address information.
    hit = it->first;
    liid = it->second;

    targets_lock.unlock();

    return true;

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
			     int delay) 
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
	throw e;
    }

    interfaces_lock.unlock();

}

// Modifies interface capture
void delivery::remove_interface(const std::string& iface,
				const std::string& filter,
				int delay)
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
			  const std::string& liid) 
{

    targets_lock.lock();

    if (addr.universe == addr.ipv4) {
	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(addr);
	targets[a] = liid;
    } else {
	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(addr);
	targets6[a] = liid;
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
void delivery::remove_target(const tcpip::address& addr) 
{
    
    targets_lock.lock();

    std::string liid;

    if (addr.universe == addr.ipv4) {
	
	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(addr);

	if (targets.find(a) == targets.end()) {
	    // Target not in the target map.  Silenty ignore.
	    targets_lock.unlock();
	    return;
	}

	// Tell all senders, target down.
	senders_lock.lock();
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->target_down(targets[a]);
	}
	senders_lock.unlock();

	targets.erase(a);

    } else {

	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(addr);

	if (targets6.find(a) == targets6.end()) {
	    // Target not in the target map.  Silenty ignore.
	    targets_lock.unlock();
	    return;
	}

	// Tell all senders, target down.
	senders_lock.lock();
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->target_down(targets6[a]);
	}

	senders_lock.unlock();

	targets6.erase(a);

    }

    targets_lock.unlock();

}

// Fetch current target list.
void delivery::get_targets(std::map<tcpip::ip4_address, std::string>& t4,
			   std::map<tcpip::ip6_address, std::string>& t6) 
{
    t4 = targets;
    t6 = targets6;
}

// Adds an endpoint
void delivery::add_endpoint(const std::string& host, unsigned int port,
			    const std::string& type) 
{

    senders_lock.lock();
    
    ep e;
    e.hostname = host;
    e.port = port;
    e.type = type;
    sender* s;

    if (senders.find(e) != senders.end()) {
	senders[e]->stop();
	senders.erase(e);
    }

    if (type == "nhis1.1") {
	s = new nhis11_sender(host, port, *this);
    } else if (type == "etsi") {
	s = new etsi_li_sender(host, port, *this);
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
			       const std::string& type)

{
    senders_lock.lock();

    ep e;
    e.hostname = host;
    e.port = port;
    e.type = type;

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

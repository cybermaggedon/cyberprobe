
#include <algorithm>
#include <pcap.h>
#include <iomanip>
#include <cassert>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cyberprobe/probe/delivery.h>

#ifdef WITH_DAG
// DAG support if available.
#include "dag_capture.h"
#endif

#include <cyberprobe/probe/vxlan_capture.h>

using namespace cyberprobe::probe;

using direction = cyberprobe::protocol::direction;

// This method studies the packet data, and PCAP datalink attribute, and:
// - Returns the IP version (4 or 6).
// - Alters the start iterator to point at the start of the IP packet.
void delivery::identify_link(const_iterator& start,
			     const_iterator& end,
			     int datalink,
			     link_info& link)
{

    if (datalink == DLT_EN10MB) {

	// Ethernet case

	// Not long enough for Ethernet frame, bail.
	if ((end - start) < 14)
	    throw std::runtime_error("Too small for Ethernet");

	// Store MAC address
	link.mac.clear();
	std::copy(start + 6, start + 12, std::back_inserter(link.mac));

	// Get IP version from Ethertype
	if (start[12] == 0x08 && start[13] == 0) {
	    link.ipv = 4;		// IPv4
	    start += 14;	// Skip the Ethernet frame.
	    return;
	} else if (start[12] == 0x86 && start[13] == 0xdd) {
	    link.ipv = 6;		// IPv6
	    start += 14;	// Skip the Ethernet frame.
	    return;
	}

	// 802.1q (VLAN)
	if (start[12] == 0x81 && start[13] == 0x00) {

	    if ((end - start) < 18)
		throw std::runtime_error("Too small for 802.1q");

	    // Get VLAN
	    link.vlan = ((start[14] & 0xf) << 8) + start[15];

	    if (start[16] == 0x08 && start[17] == 0) {
		link.ipv = 4;		// IPv4
		start += 18;		// Skip the Ethernet frame.
		return;
	    }

	    if (start[16] == 0x86 && start[17] == 0xdd) {
		link.ipv = 6;		// IPv6
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
	if (start[14] == 0x08 && start[15] == 0) link.ipv = 4;
	if (start[14] == 0x86 && start[15] == 0xdd) link.ipv = 6;

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
	    link.ipv = 4;
	else
	    link.ipv = 6;

    } else {

	// Don't know what to do.  It's not one of the link types that
	// I'm expecting.
	throw std::runtime_error("Don't know about that link type.");

    }

}

// Study an IPv4 packet, and work out if the addresses match a target
// address.  Returns true for a match, and 'device' returns the target
// device ID.
bool delivery::ipv4_match(const_iterator& start,
			  const_iterator& end,
			  const match*& m,
			  tcpip::ip4_address& hit,
                          direction& dir,
			  const link_info& link)
{

    // FIXME: What if it matches on more than one address?!
    // FIXME: Should be tagged with more than one device ID?

    // Too small to be an IP packet?
    if (end - start < 20) return false;

    // Get the source address
    tcpip::ip4_address saddr, daddr;
    saddr.addr.assign(start + 12, start + 16);
    daddr.addr.assign(start + 16, start + 20);

    // Get the target map lock.
    std::lock_guard<std::mutex> lock(targets_mutex);

    bool is_hit;
    match_state* md = 0;
    const tcpip::ip4_address* subnet = 0;
    
    is_hit = targets.get(saddr, md, subnet);

    if (is_hit) {

	assert(md != 0);
	assert(subnet != 0);

	// Cache manipulation
	if (md->mangled.find(saddr) == md->mangled.end()) {

	    std::shared_ptr<std::string> device(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->device, *device, saddr, *subnet, link);
	    expand_template(md->network, *network, saddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(auto it = senders.begin(); it != senders.end(); it++) {
		it->second->target_up(device, network, saddr);
	    }

	    md->mangled[saddr].device = device;
	    md->mangled[saddr].network = network;

	}

	m = &(md->mangled.find(saddr)->second);
	hit = saddr;
        dir = direction::FROM_TARGET;
	return true;

    }

    is_hit = targets.get(daddr, md, subnet);

    if (is_hit) {

	assert(md != 0);
	assert(subnet != 0);

	// Cache manipulation
	if (md->mangled.find(daddr) == md->mangled.end()) {

	    std::shared_ptr<std::string> device(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->device, *device, daddr, *subnet, link);
	    expand_template(md->network, *network, daddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(auto it = senders.begin(); it != senders.end(); it++) {
		it->second->target_up(device, network, daddr);
	    }

	    md->mangled[daddr].device = device;
	    md->mangled[daddr].network = network;

	}

	m = &(md->mangled.find(daddr)->second);
	hit = daddr;
        dir = direction::TO_TARGET;
	return true;

    }

    return false;

}

// Study an IPv6 packet, and work out if the addresses match a target
// address.  Returns true for a match, and 'device' returns the target device.
bool delivery::ipv6_match(const_iterator& start,
			  const_iterator& end,
			  const match*& m,
			  tcpip::ip6_address& hit,
                          direction& dir,
			  const link_info& link)
{

    // FIXME: What if it matches on more than one address?!
    // FIXME: Should be tagged with more than one device?

    // Too small to be an IPv6 packet?
    if (end - start < 40) return false;

    // Get the source,dest address
    tcpip::ip6_address saddr, daddr;
    saddr.addr.assign(start + 8, start + 24);
    daddr.addr.assign(start + 24, start + 40);

    // Get the target map lock.
    std::lock_guard<std::mutex> lock(targets_mutex);

    bool is_hit;
    match_state* md = 0;
    const tcpip::ip6_address* subnet = 0;

    is_hit = targets6.get(saddr, md, subnet);

    if (is_hit) {

	assert(md != 0);
	assert(subnet != 0);

	// Cache manipulation
	if (md->mangled6.find(saddr) == md->mangled6.end()) {

	    std::shared_ptr<std::string> device(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->device, *device, saddr, *subnet, link);
	    expand_template(md->network, *network, saddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(auto it = senders.begin(); it != senders.end(); it++) {
		it->second->target_up(device, network, saddr);
	    }

	    md->mangled6[saddr].device = device;
	    md->mangled6[saddr].network = network;

	}

	m = &(md->mangled6.find(saddr)->second);
	hit = saddr;
        dir = direction::FROM_TARGET;
	return true;

    }

    is_hit = targets6.get(daddr, md, subnet);

    if (is_hit) {

	assert(md != 0);
	assert(subnet != 0);

	// Cache manipulation
	if (md->mangled6.find(daddr) == md->mangled6.end()) {

	    std::shared_ptr<std::string> device(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->device, *device, daddr, *subnet, link);
	    expand_template(md->network, *network, daddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(auto it = senders.begin(); it != senders.end(); it++) {
		it->second->target_up(device, network, daddr);
	    }

	    md->mangled6[daddr].device = device;
	    md->mangled6[daddr].network = network;

	}

	m = &(md->mangled6.find(daddr)->second);
	hit = daddr;
        dir = direction::TO_TARGET;
	return true;

    }

    return false;

}

// The 'main' packet handling method.  This is what the caller calls when
// they have a packet.  datalink = the PCAP datalink value.
void delivery::receive_packet(timeval tv,
			      const std::vector<unsigned char>& packet,
			      int datalink)
{

    // Iterators, initially point at the start and end of the packet.
    std::vector<unsigned char>::const_iterator start = packet.begin();
    std::vector<unsigned char>::const_iterator end = packet.end();
    link_info link;

    // Start by handling the link layer.
    try {
	identify_link(start, end, datalink, link);
    } catch (...) {
	// Silently ignore exceptions.
	return;
    }

    if (link.ipv == 4) {

	// IPv4 case

	const match* m = 0;
	tcpip::ip4_address hit;
        direction dir;

	// Match the IP addresses.
	bool was_hit = ipv4_match(start, end, m, hit, dir, link);

	// No target match?
	if (!was_hit) return;

	assert(m != 0);

	// Get the senders list lock.
        std::lock_guard<std::mutex> lock(senders_mutex);

	// Now invoke destinations, and send packet to destinations.
	for(auto it = senders.begin(); it != senders.end(); it++) {
	    it->second->deliver(tv, m->device, m->network, dir, start, end);
	}

    }

    if (link.ipv == 6) {

	// IPv6 case

	const match* m = 0;
	tcpip::ip6_address hit;
        direction dir;

	// Match the IP addresses.
	bool was_hit = ipv6_match(start, end, m, hit, dir, link);

	// No target match?
	if (!was_hit) return;

	assert(m != 0);

	// Get the senders list lock.
        std::lock_guard<std::mutex> lock(senders_mutex);

	// Now invoke destinations, and send packet to destinations.
	for(auto it = senders.begin(); it != senders.end(); it++) {
	    it->second->deliver(tv, m->device, m->network, dir, start, end);
	}

    }

}

// Modifies interface capture
void delivery::add_interface(const interface::spec& sp)
{

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    if (interfaces.find(sp) != interfaces.end()) {
	interfaces[sp]->stop();
	interfaces[sp]->join();
	interfaces.erase(sp);
    }

    try {

        const std::string& iface = sp.ifa;

#ifdef WITH_DAG

	if (iface.substr(0, 3) == "dag") {

            cyberprobe::capture::dag* p =
                new cyberprobe::capture::dag(iface, delay, *this);
	    if (filter != "")
		p->add_filter(filter);
	    p->start();
	    interfaces[sp] = p;

            return;

	}

#endif

        if (iface.substr(0, 6) == "vxlan:") {

            unsigned short port = std::stoi(iface.substr(6));

            cyberprobe::capture::vxlan* p =
                new cyberprobe::capture::vxlan(port, sp.delay, *this);
            if (sp.filter != "")
                p->add_filter(sp.filter);
            p->start();
            interfaces[sp] = p;

            return;

        }

        cyberprobe::capture::interface* p =
            new cyberprobe::capture::interface(iface, sp.delay, *this);
        if (sp.filter != "")
            p->add_filter(sp.filter);
        
        p->start();
        
        interfaces[sp] = p;

    } catch (std::exception& e) {
	throw;
    }

}

// Modifies interface capture
void delivery::remove_interface(const interface::spec& sp)
{

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    if (interfaces.find(sp) != interfaces.end()) {
	interfaces[sp]->stop();
	interfaces[sp]->join();
	interfaces.erase(sp);
    }

}

void delivery::get_interfaces(std::list<interface::spec>& ii)
{

    ii.clear();

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    for(auto it = interfaces.begin(); it != interfaces.end(); it++) {
        ii.push_back(it->first);
    }

}

// Modifies the target map to include a mapping from address to target.
void delivery::add_target(const target::spec& sp)
{

    std::lock_guard<std::mutex> lock(targets_mutex);

    if (sp.universe == sp.IPv4) {
	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(sp.addr);
	targets.insert(a, sp.mask, match_state(sp.device, sp.network));
    } else {
	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(sp.addr6);
	targets6.insert(a, sp.mask, match_state(sp.device, sp.network));
    }

}

// Removes a target mapping.
void delivery::remove_target(const target::spec& sp)
{

    std::lock_guard<std::mutex> lock(targets_mutex);

    std::string device;

    if (sp.universe == sp.IPv4) {

	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(sp.addr);

	match_state* ms;
	bool hit = targets.get(a, ms);

	if (hit) {

	    // Tell all senders, target down.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(auto it = senders.begin(); it != senders.end(); it++) {

		for(std::map<tcpip::ip4_address,match>::iterator it2 =
			ms->mangled.begin();
		    it2 != ms->mangled.end();
		    it2++) {
		    it->second->target_down(it2->second.device,
					    it2->second.network);
		}

		for(std::map<tcpip::ip6_address,match>::iterator it2 =
			ms->mangled6.begin();
		    it2 != ms->mangled6.end();
		    it2++) {
		    it->second->target_down(it2->second.device,
					    it2->second.network);
		}

	    }

	}
	
	targets.remove(a, sp.mask);

    } else {

	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(sp.addr6);

	match_state* ms;
	bool hit = targets6.get(a, ms);

	if (hit) {

	    // Tell all senders, target down.
            std::lock_guard<std::mutex> lock(senders_mutex);

	    for(auto it = senders.begin(); it != senders.end(); it++) {

		for(std::map<tcpip::ip4_address,match>::iterator it2 =
			ms->mangled.begin();
		    it2 != ms->mangled.end();
		    it2++) {
		    it->second->target_down(it2->second.device,
					    it2->second.network);
		}

		for(std::map<tcpip::ip6_address,match>::iterator it2 =
			ms->mangled6.begin();
		    it2 != ms->mangled6.end();
		    it2++) {
		    it->second->target_down(it2->second.device,
					    it2->second.network);
		}

	    }

	}
	
	targets6.remove(a, sp.mask);

    }

}

// Fetch current target list.
void delivery::get_targets(std::list<target::spec>& lst)
{

    lst.clear();
    
    std::lock_guard<std::mutex> lock(targets_mutex);

    for(auto mask = targets.m.begin(); mask != targets.m.end(); mask++) {
        for(auto addr = mask->second.begin(); addr != mask->second.end();
            addr++) {
            target::spec sp;
            sp.addr = addr->first;
            sp.mask = mask->first;
            sp.universe = sp.IPv4;
            sp.device = addr->second.device;
            sp.network = addr->second.network;
            lst.push_back(sp);
        }
    }
    
    for(auto mask = targets6.m.begin(); mask != targets6.m.end(); mask++) {
        for(auto addr = mask->second.begin(); addr != mask->second.end();
            addr++) {
            target::spec sp;
            sp.addr6 = addr->first;
            sp.mask = mask->first;
            sp.universe = sp.IPv6;
            sp.device = addr->second.device;
            sp.network = addr->second.network;
            lst.push_back(sp);
        }
    }

}

// Adds an endpoint
void delivery::add_endpoint(const endpoint::spec& sp)
{

    std::lock_guard<std::mutex> lock(senders_mutex);

    sender* s;

    if (senders.find(sp) != senders.end()) {
	senders[sp]->stop();
	senders[sp]->join();
	senders.erase(sp);
    }

    if (sp.type == "nhis1.1") {
        std::map<std::string,std::string> params = {
            {"certificate", sp.certificate_file},
            {"key", sp.key_file},
            {"chain", sp.trusted_ca_file},
        };
	s = new nhis11_sender(sp.hostname, sp.port, sp.transport, params,
                              *this);
    } else if (sp.type == "etsi") {
        std::map<std::string,std::string> params = {
            {"certificate", sp.certificate_file},
            {"key", sp.key_file},
            {"chain", sp.trusted_ca_file},
        };
	s = new etsi_li_sender(sp.hostname, sp.port, sp.transport, params,
                               *this);
    } else {
	throw std::runtime_error("Endpoint type not known.");
    }

    s->start();
    senders[sp] = s;

}

// Removes an endpoint
void delivery::remove_endpoint(const endpoint::spec& sp)
{

    std::lock_guard<std::mutex> lock(senders_mutex);

    if (senders.find(sp) != senders.end()) {
	senders[sp]->stop();
	senders[sp]->join();
	senders.erase(sp);
    }

}

// Fetch current target list.
void delivery::get_endpoints(std::list<endpoint::spec>& info)
{

    std::lock_guard<std::mutex> lock(senders_mutex);

    info.clear();

    for(auto it = senders.begin(); it != senders.end(); it++) {
        info.push_back(it->first);
    }

}

void delivery::expand_template(const std::string& in,
			       std::string& out,
			       const tcpip::address& addr,
			       const tcpip::address& subnet,
			       const link_info& link)
{

    out.erase();

    for(std::string::const_iterator it = in.begin(); it != in.end(); it++) {

	if (*it == '%') {

	    it++;

	    if (it == in.end()) {
		out.push_back('%');
		continue;
	    }

	    if (*it == 'i') {
		std::string a;
		addr.to_string(a);
		out.append(a);
		continue;
	    }

	    if (*it == 's') {
		std::string a;
		subnet.to_string(a);
		out.append(a);
		continue;
	    }

	    if (*it == 'm') {
		std::ostringstream buf;
		bool first = true;
		for(std::vector<unsigned char>::const_iterator it =
                        link.mac.begin();
		    it != link.mac.end();
		    it++) {
		    if (first)
			first = false;
		    else
			buf << ':';
		    buf << std::hex << std::setw(2) << std::setfill('0')
			<< (unsigned int)*it;
		}
		out.append(buf.str());
		continue;
	    }

	    if (*it == 'v') {
		std::ostringstream buf;
		buf << std::dec << std::setw(1) << link.vlan;
		out.append(buf.str());
		continue;
	    }

	    out.push_back(*it);
	    continue;

	} else

	    out.push_back(*it);

    }

}


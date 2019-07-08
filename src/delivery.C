
#include <algorithm>
#include <pcap.h>
#include <iomanip>
#include <cassert>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "delivery.h"

#ifdef WITH_DAG
// DAG support if available.
#include "dag_capture.h"
#endif

#include <vxlan_capture.h>

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
// address.  Returns true for a match, and 'liid' returns the target LIID.
bool delivery::ipv4_match(const_iterator& start,
			  const_iterator& end,
			  const match*& m,
			  tcpip::ip4_address& hit,
                          cybermon::direction& dir,
			  const link_info& link)
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

	    std::shared_ptr<std::string> liid(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->liid, *liid, saddr, *subnet, link);
	    expand_template(md->network, *network, saddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(std::map<ep,sender*>::iterator it = senders.begin();
		it != senders.end();
		it++) {
		it->second->target_up(liid, network, saddr);
	    }

	    md->mangled[saddr].liid = liid;
	    md->mangled[saddr].network = network;

	}

	m = &(md->mangled.find(saddr)->second);
	hit = saddr;
        dir = cybermon::FROM_TARGET;
	return true;

    }

    is_hit = targets.get(daddr, md, subnet);

    if (is_hit) {

	assert(md != 0);
	assert(subnet != 0);

	// Cache manipulation
	if (md->mangled.find(daddr) == md->mangled.end()) {

	    std::shared_ptr<std::string> liid(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->liid, *liid, daddr, *subnet, link);
	    expand_template(md->network, *network, daddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(std::map<ep,sender*>::iterator it = senders.begin();
		it != senders.end();
		it++) {
		it->second->target_up(liid, network, daddr);
	    }

	    md->mangled[daddr].liid = liid;
	    md->mangled[daddr].network = network;

	}

	m = &(md->mangled.find(daddr)->second);
	hit = daddr;
        dir = cybermon::TO_TARGET;
	return true;

    }

    return false;

}

// Study an IPv6 packet, and work out if the addresses match a target
// address.  Returns true for a match, and 'liid' returns the target LIID.
bool delivery::ipv6_match(const_iterator& start,
			  const_iterator& end,
			  const match*& m,
			  tcpip::ip6_address& hit,
                          cybermon::direction& dir,
			  const link_info& link)
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

	    std::shared_ptr<std::string> liid(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->liid, *liid, saddr, *subnet, link);
	    expand_template(md->network, *network, saddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(std::map<ep,sender*>::iterator it = senders.begin();
		it != senders.end();
		it++) {
		it->second->target_up(liid, network, saddr);
	    }

	    md->mangled6[saddr].liid = liid;
	    md->mangled6[saddr].network = network;

	}

	m = &(md->mangled6.find(saddr)->second);
	hit = saddr;
        dir = cybermon::FROM_TARGET;
	return true;

    }

    is_hit = targets6.get(daddr, md, subnet);

    if (is_hit) {

	assert(md != 0);
	assert(subnet != 0);

	// Cache manipulation
	if (md->mangled6.find(daddr) == md->mangled6.end()) {

	    std::shared_ptr<std::string> liid(new std::string);
	    std::shared_ptr<std::string> network(new std::string);

	    expand_template(md->liid, *liid, daddr, *subnet, link);
	    expand_template(md->network, *network, daddr, *subnet, link);

	    // Tell all senders, target up.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(std::map<ep,sender*>::iterator it = senders.begin();
		it != senders.end();
		it++) {
		it->second->target_up(liid, network, daddr);
	    }

	    md->mangled6[daddr].liid = liid;
	    md->mangled6[daddr].network = network;

	}

	m = &(md->mangled6.find(daddr)->second);
	hit = daddr;
        dir = cybermon::TO_TARGET;
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
        cybermon::direction dir;

	// Match the IP addresses.
	bool was_hit = ipv4_match(start, end, m, hit, dir, link);

	// No target match?
	if (!was_hit) return;

	assert(m != 0);

	// Get the senders list lock.
        std::lock_guard<std::mutex> lock(senders_mutex);

	// Now invoke destinations, and send packet to destinations.
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->deliver(tv, m->liid, m->network, dir, start, end);
	}

    }

    if (link.ipv == 6) {

	// IPv6 case

	const match* m = 0;
	tcpip::ip6_address hit;
        cybermon::direction dir;

	// Match the IP addresses.
	bool was_hit = ipv6_match(start, end, m, hit, dir, link);

	// No target match?
	if (!was_hit) return;

	assert(m != 0);

	// Get the senders list lock.
        std::lock_guard<std::mutex> lock(senders_mutex);

	// Now invoke destinations, and send packet to destinations.
	for(std::map<ep,sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    it->second->deliver(tv, m->liid, m->network, dir, start, end);
	}

    }

}

// Modifies interface capture
void delivery::add_interface(const std::string& iface,
			     const std::string& filter,
			     float delay)
{

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    intf i;
    i.interface = iface;
    i.filter = filter;
    i.delay = delay;

    if (interfaces.find(i) != interfaces.end()) {
	interfaces[i]->stop();
	interfaces[i]->join();
	interfaces.erase(i);
    }

    try {

#ifdef WITH_DAG

	if (iface.substr(0, 3) == "dag") {

	    dag_dev* p = new dag_dev(iface, delay, *this);
	    if (filter != "")
		p->add_filter(filter);
	    p->start();
	    interfaces[i] = p;

            return;

	}

#endif

        if (iface.substr(0, 6) == "vxlan:") {

            unsigned short port = std::stoi(iface.substr(6));

            vxlan_capture* p = new vxlan_capture(port, delay, *this);
            if (filter != "")
                p->add_filter(filter);
            p->start();
            interfaces[i] = p;

            return;

        }

        pcap_dev* p = new pcap_dev(iface, delay, *this);
        if (filter != "")
            p->add_filter(filter);
        
        p->start();
        
        interfaces[i] = p;

    } catch (std::exception& e) {
	throw;
    }

}

// Modifies interface capture
void delivery::remove_interface(const std::string& iface,
				const std::string& filter,
				float delay)
{

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    intf i;
    i.interface = iface;
    i.filter = filter;
    i.delay = delay;

    if (interfaces.find(i) != interfaces.end()) {
	interfaces[i]->stop();
	interfaces[i]->join();
	interfaces.erase(i);
    }

}

void delivery::get_interfaces(std::list<interface_info>& ii)
{

    ii.clear();

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    for(std::map<intf,capture_dev*>::iterator it = interfaces.begin();
	it != interfaces.end();
	it++) {
	interface_info inf;
	inf.interface = it->first.interface;
	inf.filter = it->first.filter;
	inf.delay = it->first.delay;
	ii.push_back(inf);
    }

}

// Modifies the target map to include a mapping from address to target.
void delivery::add_target(const tcpip::address& addr,
			  unsigned int mask,
			  const std::string& liid,
			  const std::string& network)
{

    std::lock_guard<std::mutex> lock(targets_mutex);

    if (addr.universe == addr.ipv4) {
	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(addr);
	targets.insert(a, mask, match_state(liid, network));
    } else {
	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(addr);
	targets6.insert(a, mask, match_state(liid, network));
    }

}

// Removes a target mapping.
void delivery::remove_target(const tcpip::address& addr, unsigned int mask)
{

    std::lock_guard<std::mutex> lock(targets_mutex);

    std::string liid;

    if (addr.universe == addr.ipv4) {

	const tcpip::ip4_address& a =
	    reinterpret_cast<const tcpip::ip4_address&>(addr);

	match_state* ms;
	bool hit = targets.get(a, ms);

	if (hit) {

	    // Tell all senders, target down.
            std::lock_guard<std::mutex> lock(senders_mutex);
	    for(std::map<ep,sender*>::iterator it = senders.begin();
		it != senders.end();
		it++) {

		for(std::map<tcpip::ip4_address,match>::iterator it2 =
			ms->mangled.begin();
		    it2 != ms->mangled.end();
		    it2++) {
		    it->second->target_down(it2->second.liid,
					    it2->second.network);
		}

		for(std::map<tcpip::ip6_address,match>::iterator it2 =
			ms->mangled6.begin();
		    it2 != ms->mangled6.end();
		    it2++) {
		    it->second->target_down(it2->second.liid,
					    it2->second.network);
		}

	    }

	}
	
	targets.remove(a, mask);

    } else {

	const tcpip::ip6_address& a =
	    reinterpret_cast<const tcpip::ip6_address&>(addr);

	match_state* ms;
	bool hit = targets6.get(a, ms);

	if (hit) {

	    // Tell all senders, target down.
            std::lock_guard<std::mutex> lock(senders_mutex);

	    for(std::map<ep,sender*>::iterator it = senders.begin();
		it != senders.end();
		it++) {

		for(std::map<tcpip::ip4_address,match>::iterator it2 =
			ms->mangled.begin();
		    it2 != ms->mangled.end();
		    it2++) {
		    it->second->target_down(it2->second.liid,
					    it2->second.network);
		}

		for(std::map<tcpip::ip6_address,match>::iterator it2 =
			ms->mangled6.begin();
		    it2 != ms->mangled6.end();
		    it2++) {
		    it->second->target_down(it2->second.liid,
					    it2->second.network);
		}

	    }

	}
	
	targets6.remove(a, mask);

    }

}

// Fetch current target list.
void delivery::get_targets(std::map<int,
			   std::map<tcpip::ip4_address, std::string> >& t4,
			   std::map<int,
			   std::map<tcpip::ip6_address, std::string> >& t6)
{
#ifdef FIXME
    // FIXME: Doesn't return anything... it should!
    t4 = targets;
    t6 = targets6;
#endif
}

// Adds an endpoint
void delivery::add_endpoint(const std::string& host, unsigned int port,
			    const std::string& type,
			    const std::string& transport,
			    const std::map<std::string, std::string>& params)
{

    std::lock_guard<std::mutex> lock(senders_mutex);

    ep e(host, port, type, transport, params);

    sender* s;

    if (senders.find(e) != senders.end()) {
	senders[e]->stop();
	senders[e]->join();
	senders.erase(e);
    }

    if (type == "nhis1.1") {
	s = new nhis11_sender(host, port, transport, params, *this);
    } else if (type == "etsi") {
	s = new etsi_li_sender(host, port, transport, params, *this);
    } else {
	throw std::runtime_error("Endpoint type not known.");
    }

    s->start();
    senders[e] = s;

}

// Removes an endpoint
void delivery::remove_endpoint(const std::string& host, unsigned int port,
			       const std::string& type,
			       const std::string& transport,
			       const std::map<std::string, std::string>& params)
{

    std::lock_guard<std::mutex> lock(senders_mutex);

    ep e(host, port, type, transport, params);

    if (senders.find(e) != senders.end()) {
	senders[e]->stop();
	senders[e]->join();
	senders.erase(e);
    }

}

// Fetch current target list.
void delivery::get_endpoints(std::list<sender_info>& info)
{

    std::lock_guard<std::mutex> lock(senders_mutex);

    info.clear();
    for(std::map<ep,sender*>::iterator it = senders.begin();
	it != senders.end();
	it++) {
	sender_info inf;
	it->second->get_info(inf);
	info.push_back(inf);
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


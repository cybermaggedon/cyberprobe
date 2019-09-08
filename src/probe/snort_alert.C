
#include <iostream>
#include <sys/types.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string>
#include <arpa/inet.h>

#include <cyberprobe/network/socket.h>
#include <cyberprobe/probe/snort_alert.h>

namespace cyberprobe {

namespace probe {

namespace snort_alert {

    void to_json(json& j, const spec& s) {
        j = json{{"path", s.path}, {"duration", s.duration}};
    }

    void from_json(const json& j, spec& s) {
        j.at("path").get_to(s.path);
        j.at("duration").get_to(s.duration);
    }

    std::string spec::get_hash() const { 
        json j = *this;
        return " " + j.dump();            
    }

////////////////////////////////////////////////////////////////////////////
//
// The following stuff describes Snort alert format.
//
////////////////////////////////////////////////////////////////////////////

// FIXME: IPv6 support has not been tested.
// FIXME: Need to add a delay to make this alerting affective - it won't
// capture the packet which caused the alert.

// Message length;
const int alert_message_len = 256;

// Snort event
struct snort_event {
    uint32_t sig_generator;	// Signature generator.
    uint32_t sig_id;		// Signature ID
    uint32_t sig_rev;		// Signature revision
    uint32_t classification;	// Classification from signature.
    uint32_t priority;		// Priority from signature.
    uint32_t event_id;		// Event ID
    uint32_t event_ref;		// Event reference.

    // Timeval of event time
    uint32_t sec;
    uint32_t usec;
};

struct snort_pcap_header {
    // PCAP header, everything's 32-bit.
    uint32_t sec;
    uint32_t usec;
    uint32_t caplen;
    uint32_t reallen;
};

// Snort alert
struct snort_alert {
    unsigned char message[alert_message_len]; // Message from rule
    snort_pcap_header pcaphdr;	// PCAP header
    uint32_t dlt_hdr;		// Data link header start
    uint32_t net_hdr;		// Network header start.
    uint32_t trans_hdr;		// Transport header start.
    uint32_t data;		// Data start.
    uint32_t flags;		// Flags, 1 = no packet, 2 = no transport hdr
    unsigned char pkt[65535];	// Packet data.
    snort_event event;		// Snort event.
};

// Snort alerter thread body.
void snort_alerter::run()
{

    // UNIX socket to receive alerts.
    tcpip::unix_socket sock;

    // Queue of 'events'.  This queue holds time values when we need to
    // rescan the dynamically targeted map to take 'old' IPs off.
    std::deque<long> timeout_events;

    // Map from IP address to take-down time.
    std::map<tcpip::ip4_address, long> timeout4;
    std::map<tcpip::ip6_address, long> timeout6; // For IPv6.

    // Bind the socket to its pathname

    try {
	sock.bind(sp.path);
    } catch (...) {
	std::cerr << "Couldn't bind snort alert to path " << sp.path
		  << std::endl;
	return;
    }

    // Loop until shutdown.
    while (running) {

	// Alert message from snort.
	snort_alert alert;

	// Poll for activity on the socket.
	bool activ = sock.poll(1.0);

	// If closing down, time to leave.
	if (!running) break;

	// Activity on socket?
	if (activ) {

	    // Get the alert message.
	    int recvd = sock.read(reinterpret_cast<char*>(&alert), 
				  sizeof(alert));
	    
	    if (recvd == 0) break;
	    if (recvd < 0) {
		perror("recv");
		break;
	    }

	    // Check we get a full message.
	    if (recvd != sizeof(alert)) continue;

	    // Ignore if no packet structure.
	    if (alert.flags & 1) continue;
	    
	    // Locate the IP header
	    unsigned char* ip_hdr = alert.pkt + alert.net_hdr;

	    tcpip::ip4_address src4;
	    tcpip::ip6_address src6;

	    tcpip::address* src;
	    bool targeting = false;

	    unsigned int mask;

            bool ipv4 = false;

	    // IP version.
	    if ((ip_hdr[0] & 0xf0) == 0x40) {

		// IPv4 case.
		src4.addr.assign(ip_hdr + 12, ip_hdr + 16);
                src = &src4;
                ipv4 = true;
		targeting = (timeout4.find(src4) != timeout4.end());
		// Just targeting single IP address, so use full mask.
		mask = 32;	

	    } else {

		// IPv6 case.
		src6.addr.assign(ip_hdr + 8, ip_hdr + 24);
                src = &src6;
                ipv4 = false;
		targeting = (timeout6.find(src6) != timeout6.end());
		// Just targeting single IP address, so use full mask.
		mask = 128;

	    }
	    
	    // If not curently targeting, switch on targeting.
	    if (!targeting) {

		// Snort signature ID
		long sid = alert.event.sig_id;

		std::cout << "Snort alert: " << alert.message << std::endl;
		std::cout << "Hit on signature ID " << sid
			  << ", targeting " << *src
			  << std::endl;

		std::ostringstream buf;
		buf << "snort." << sid << ".device";

		std::ostringstream fallb;
		fallb << "SNORT";
		for(std::vector<unsigned char>::iterator it = src->addr.begin();
		    it != src->addr.end();
		    it++) {
                    fallb.width(2);
                    fallb.fill('0');
                    fallb << std::hex << (int) *it;
		}

		std::string device = deliv.get_parameter(buf.str(),
                                                         fallb.str());

		// FIXME: Can't control network parameter.
                target::spec sp;
                if (ipv4) {
                    sp.addr = src4;
                    sp.universe = sp.IPv4;
                } else {
                    sp.addr6 = src6;
                    sp.universe = sp.IPv6;
                }
                sp.mask = mask;
                sp.device = device;
                sp.network = "";
		deliv.add_target(sp);

	    }

	    // Update timeout management structures.
	    long to = time(0) + sp.duration;
	    timeout_events.push_back(to);
	    if (src->universe == src->ipv4)
		timeout4[src4] = to;
	    else
		timeout6[src6] = to;

	}

	// Now take off targeting which has expired.
	time_t now = time(0);

	// Loop through the timeout map if a event comes up.
	while (!timeout_events.empty() && 
	       timeout_events.front() <= now) {

	    // Discard the time event.
	    timeout_events.pop_front();

	    // FIXME: This iterate stuff is pants.  Use reaper.

	    // iterate through timeout map, looking for addresses wich have
	    // expired.
	    for(std::map<tcpip::ip4_address, long>::iterator it =
		    timeout4.begin();
		it != timeout4.end();
		) {

		if (it->second <= now) {

		    std::cout << "Stopped targeting on " 
			      << it->first
			      << std::endl;

		    // IPv4 address, use full address mask.
                    target::spec sp;
                    sp.addr = it->first;
                    sp.universe = sp.IPv4;
                    sp.mask = 32;
		    deliv.remove_target(sp);

		    auto nxt = it;
		    nxt++;
		    timeout4.erase(it);
		    it = nxt;

		} else

		    it++;

	    }

	    // iterate through timeout map, looking for addresses wich have
	    // expired.
	    for(std::map<tcpip::ip6_address, long>::iterator it =
		    timeout6.begin();
		it != timeout6.end();
		) {

		if (it->second <= now) {

		    std::cout << "Stopped targeting on " 
			      << it->first
			      << std::endl;

		    // IPv6 address, use full address mask.
                    target::spec sp;
                    sp.addr6 = it->first;
                    sp.universe = sp.IPv6;
                    sp.mask = 128;

		    deliv.remove_target(sp);

		    auto nxt = it;
		    nxt++;
		    timeout6.erase(it);
		    it = nxt;

		} else

		    it++;

	    }

	}

    }

    // Before closing down, remove all IPv4 targeting.
    for(std::map<tcpip::ip4_address, long>::iterator it =
	    timeout4.begin();
	it != timeout4.end();
	it++) {

	std::cout << "Stopped targeting on " 
		  << it->first
		  << std::endl;

	// Currently only targeting single addresses, use full address mask.
        target::spec sp;
        sp.addr = it->first;
        sp.universe = sp.IPv4;
        sp.mask = 32;
	deliv.remove_target(sp);

    }

    // Before closing down, remove all IPv6 targeting.
    for(std::map<tcpip::ip6_address, long>::iterator it =
	    timeout6.begin();
	it != timeout6.end();
	it++) {

	std::cout << "Stopped targeting on " 
		  << it->first
		  << std::endl;

	// Currently only targeting single addresses, use full address mask.
        target::spec sp;
        sp.addr6 = it->first;
        sp.universe = sp.IPv6;
        sp.mask = 128;
	deliv.remove_target(sp);

    }

}

}

}

}


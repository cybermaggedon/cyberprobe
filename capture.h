
////////////////////////////////////////////////////////////////////////////
//
// PACKET CAPTURE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CAPTURE_H
#define CAPTURE_H

#include "packet_capture.h"
#include "packet_consumer.h"
#include "thread.h"

#include <sys/time.h>

#include <queue>

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class capture_dev : public interface_capture, public threads::thread {
private:

    struct delayed_packet {
	std::vector<unsigned char> packet;
	struct timeval exit_time;
    };

    std::queue<delayed_packet> delay_line;

    // Handle to the deliver engine.
    packet_consumer& deliv;

    // Filter applied to packets.
    //    std::string filter;

    // PCAP's datalink enumerator - describes the type of layer 2 wrapping
    // on the IP packet.
    int datalink;

    // Seconds of delay
    float delay;

    // Delay converted to timeval form.
    struct timeval delay_val;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    capture_dev(const std::string& i, float delay, packet_consumer& d) : 
	interface_capture(i), deliv(d) { 
	datalink = pcap_datalink(p); 
	this->delay = delay;
    }

    // Destructor.
    virtual ~capture_dev() {}

    // Packet handler.
    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* bytes);
};

#endif


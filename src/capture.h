
////////////////////////////////////////////////////////////////////////////
//
// PACKET CAPTURE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CAPTURE_H
#define CAPTURE_H

#include <cybermon/packet_capture.h>
#include <cybermon/thread.h>
#include <packet_consumer.h>

#include <sys/time.h>

#include <queue>

class capture_dev : public threads::thread {
  public:
    virtual ~capture_dev() {}
    virtual void stop() = 0;
    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* bytes) = 0;
};

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class pcap_dev : public capture_dev, public interface_capture {
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
    pcap_dev(const std::string& i, float delay, packet_consumer& d) : 
	interface_capture(i), deliv(d) { 
	datalink = pcap_datalink(p); 
	this->delay = delay;
    }

    // Destructor.
    virtual ~pcap_dev() {}

    // Packet handler.
    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* bytes);

    virtual void stop() {
	interface_capture::stop();
    }

};

#endif



////////////////////////////////////////////////////////////////////////////
//
// PACKET CAPTURE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CAPTURE_H
#define CAPTURE_H

#include <cybermon/packet_capture.h>
#include <packet_consumer.h>

#include <queue>
#include <thread>

class capture_dev {
public:
    virtual ~capture_dev() {}
    virtual void stop() = 0;
    virtual void start() = 0;
    virtual void join() = 0;
};

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class pcap_dev : public pcap_interface , public capture_dev {
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

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    pcap_dev(const std::string& i, float delay, packet_consumer& d) :
	pcap_interface(i), deliv(d) {
	datalink = pcap_datalink(p);
	this->delay = delay;
	thr = 0;
    }

    // Destructor.
    virtual ~pcap_dev() {
	// FIXME: Wait for it to stop?
	delete thr;
    }

    // Packet handler.
    virtual void handle(timeval tv, unsigned long len, unsigned long captured,
			const unsigned char* bytes);

    virtual void stop() {
	pcap_interface::stop();
	running = false;
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&pcap_dev::run, this);
    }

};

#endif



#ifndef DAG_CAPTURE_H
#define DAG_CAPTURE_H

#include "capture.h"

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class dag_dev : public capture_dev {
private:

    struct delayed_packet {
	std::vector<unsigned char> packet;
	struct timeval exit_time;
    };

    std::string iface;

    std::queue<delayed_packet> delay_line;

    // Handle to the deliver engine.
    packet_consumer& deliv;

    // Seconds of delay
    float delay;

    // Delay converted to timeval form.
    struct timeval delay_val;

    // PCAP's datalink enumerator - describes the type of layer 2 wrapping
    // on the IP packet.
    int datalink;

    // Set to false to stop.
    bool running;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    dag_dev(const std::string& i, float delay, packet_consumer& d) : 
      deliv(d) { 
	  this->delay = delay;
	  this->datalink = DLT_EN10MB; // FIXME: Hard-coded?
	  this->iface = i;
	  this->running = true;
    }

    // Destructor.
    virtual ~dag_dev() {}

    // Packet handler.
    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* bytes);

    virtual void stop() {
	running = false;
    }

};

#endif



#ifndef VXLAN_CAPTURE_H
#define VXLAN_CAPTURE_H

#include <capture.h>

#include <sys/time.h>

#include <thread>

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class vxlan_capture : public capture_dev {
private:

    struct delayed_packet {
	std::vector<unsigned char> packet;
	struct timeval exit_time;
    };

    unsigned short port;

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

    // Packet filter.
    std::string filter;

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    vxlan_capture(unsigned short port, float delay, packet_consumer& d) :
        deliv(d) {
        this->delay = delay;
        this->datalink = DLT_EN10MB; // FIXME: Hard-coded?
        this->port = port;
        this->running = true;
    }

    // Destructor.
    virtual ~vxlan_capture() {}

    // Packet handler.
    void handle(const timeval& tv, 
                std::vector<unsigned char>::const_iterator s,
                std::vector<unsigned char>::const_iterator e);

    virtual void stop() {
	running = false;
    }

    void add_filter(const std::string& spec) {
	filter = spec;
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&vxlan_capture::run, this);
    }

};

#endif


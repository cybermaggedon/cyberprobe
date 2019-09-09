
#ifndef VXLAN_CAPTURE_H
#define VXLAN_CAPTURE_H

#include <cyberprobe/probe/capture.h>

#include <sys/time.h>

#include <thread>

namespace cyberprobe {

namespace capture {

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class vxlan : public filtering_device {
private:

    unsigned short port;
    bool running;

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    vxlan(unsigned short port, float delay, packet_consumer& d) :
        filtering_device(d, delay, DLT_EN10MB) {
        this->port = port;
        this->running = true;
    }

    // Destructor.
    virtual ~vxlan() {}

    virtual void stop() {
	running = false;
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&vxlan::run, this);
    }

};

};

};

#endif


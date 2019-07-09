
#ifndef VXLAN_CAPTURE_H
#define VXLAN_CAPTURE_H

#include <capture.h>

#include <sys/time.h>

#include <thread>

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class vxlan_capture : public filtering_dev {
private:

    unsigned short port;
    bool running;

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    vxlan_capture(unsigned short port, float delay, packet_consumer& d) :
        filtering_dev(d, delay, DLT_EN10MB) {
        this->port = port;
        this->running = true;
    }

    // Destructor.
    virtual ~vxlan_capture() {}

    virtual void stop() {
	running = false;
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


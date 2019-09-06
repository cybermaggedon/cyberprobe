
#ifndef DAG_CAPTURE_H
#define DAG_CAPTURE_H

#include "capture.h"
#include <pcap.h>
#include <pcap-bpf.h>

#include <sys/time.h>

namespace cyberprobe {

namespace capture {

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class dag : public filtering_dev {
private:

    std::string iface;

    // Set to false to stop.
    bool running;

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    dag_dev(const std::string& i, float delay, packet_consumer& d) :
        filtering_dev(d, delay, DLT_EN10MB) {
        this->iface = i;
        this->running = true;
    }

    // Destructor.
    virtual ~dag_dev() {}

    virtual void stop() {
	running = false;
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&dag_dev::run, this);
    }

};

};

};

#endif


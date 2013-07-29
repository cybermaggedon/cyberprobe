
////////////////////////////////////////////////////////////////////////////
//
// INTERFACE RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef INTERFACE_H
#define INTERFACE_H

#include "capture.h"

// An interface specification
class iface_spec : public specification {
public:

    // Type is 'iface'
    virtual std::string get_type() const { return "iface"; }

    // Interface name e.g. eth0
    std::string ifa;

    // Capture filter.
    std::string filter;

    // Delay
    int delay;

    // Constructors.
    iface_spec() {}
    iface_spec(const std::string& ifa) { this->ifa = ifa; delay = 0; }

    // Hash is <interface>:<filter>:<delay>
    virtual std::string get_hash() const { 
      std::ostringstream buf;
      buf << ifa << ":" << filter << ":" << delay;
      return buf.str();
}

};

// An interface resources, basically wraps the 'cap' class in a thread
// which can started and stopped.
class iface : public resource, public threads::thread {
private:

    // Specification.
    const iface_spec& spec;

    // Interface capture.
    capture_dev* c;

    // Reference to the delivery engine.
    delivery& deliv;

public:

    // Constructor.
    iface(const iface_spec& spec, delivery& d) : 
	spec(spec), deliv(d) { c = 0; }

    // Start method.
    virtual void start() { 
      c = new capture_dev(spec.ifa, deliv, spec.delay);
	if (spec.filter != "")
	    c->add_filter(spec.filter);
	
	thread::start(); 
	std::cerr << "Capture on interface " << spec.ifa << " started."
		  << std::endl;
	if (spec.filter != "")
	    std::cerr << "  filter: " << spec.filter << std::endl;
	if (spec.delay != 0)
	    std::cerr << "  delay: " << spec.delay << std::endl;
    }

    // Stop method.
    virtual void stop() { 
	if (c) {
	    c->stop();
	    join();
	    delete c;
	}
	std::cerr << "Capture on interface " << spec.ifa << " stopped."
		  << std::endl;
    }

    // Thread body, just invoke the capture.
    virtual void run() {
	c->run();
    }

};

#endif


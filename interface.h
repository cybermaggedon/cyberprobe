
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
class iface : public resource {
private:

    // Specification.
    const iface_spec& spec;

    // Reference to the delivery engine.
    delivery& deliv;

public:

    // Constructor.
    iface(const iface_spec& spec, delivery& d) : 
	spec(spec), deliv(d) {}

    // Start method.
    virtual void start() { 

	deliv.add_interface(spec.ifa, spec.filter, spec.delay);

	std::cerr << "Capture on interface " << spec.ifa << " started."
		  << std::endl;
	if (spec.filter != "")
	    std::cerr << "  filter: " << spec.filter << std::endl;
	if (spec.delay != 0)
	    std::cerr << "  delay: " << spec.delay << std::endl;

    }

    // Stop method.
    virtual void stop() { 
	deliv.remove_interface(spec.ifa, spec.filter, spec.delay);
	std::cerr << "Capture on interface " << spec.ifa << " stopped."
		  << std::endl;
    }

};

#endif


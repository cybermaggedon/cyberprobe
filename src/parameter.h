
////////////////////////////////////////////////////////////////////////////
//
// PARAMETER RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef PARAMETER_H
#define PARAMETER_H

#include <cybermon/resource.h>

#include "delivery.h"

// A paramter, represents a key/val pair.
class parameter_spec : public specification {
public:

    // Type is 'target'.
    virtual std::string get_type() const { return "parameter"; }

    // LIID.
    std::string key;
    std::string val;

    // Constructors.
    parameter_spec(const std::string& key, const std::string& val) { 
	this->key = key; this->val = val;
    }

    // Hash is form key=val
    virtual std::string get_hash() const { 
	return key + "=" + val;
    }

};

// Parameter resource.  Just instantiated as changes to the delivery engine.
class parameter : public resource {
private:

    // Spec.
    const parameter_spec& spec;

    // Delivery engine reference.
    delivery& deliv;

public:

    // Constructor.
    parameter(const parameter_spec& spec, delivery& d) : 
	spec(spec), deliv(d) { }

    // Start method, change the delivery engine mapping.
    virtual void start() { 
	deliv.add_parameter(spec.key, spec.val);
	std::cerr << "Added parameter " << spec.key << "=" << spec.val 
		  << std::endl;
    }

    // Stop method, remove the mapping.
    virtual void stop() { 
	deliv.remove_parameter(spec.key);
	std::cerr << "Removed parameter " << spec.key << "=" << spec.val 
		  << std::endl;
    }

};

#endif



////////////////////////////////////////////////////////////////////////////
//
// ENDPOINT RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef ENDPOINT_H
#define ENDPOINT_H

// An endpoint, describes where to send stuff.
class endpoint_spec : public cybermon::specification {
public:

    // Type is 'endpoint'.
    virtual std::string get_type() const { return "endpoint"; }

    // Endpoint parameters.
    std::string hostname;
    unsigned short port;
    std::string type;

    // Constructors.
    endpoint_spec() {}
    endpoint_spec(const std::string& hostname, unsigned short port,
		  const std::string& type) {
	this->hostname = hostname; this->port = port; this->type = type;
    }

    // Hash is form <space> + host:port.
    virtual std::string get_hash() const { 
	std::ostringstream buf;

	// See that space before the hash?  It means that endpoint
	// hashes are "less than" other hashes, which means they are at the
	// front of the set.  This means endpoints are started before
	// targets.

	// The end result of that, is that we know endpoints will be
	// configured before targets are added to the delivery engine,
	// which means that 'target up' messages will be sent on targets
	// configured in the config file.

	buf << " " << hostname << ":" << port << ":" << type;
	return buf.str();
    }

};

// Endpoint resource.  The endpoint resources are just instantiated as
// changes to the endpoint list in the delivery engine.
class endpoint : public cybermon::resource {
private:

    // Spec.
    const endpoint_spec& spec;

    // Delivery engine reference.
    delivery& deliv;

public:

    // Constructor.
    endpoint(const endpoint_spec& spec, delivery& d) : 
	spec(spec), deliv(d) { }

    // Start method, change the delivery engine mapping.
    virtual void start() { 

	deliv.add_endpoint(spec.hostname, spec.port, spec.type);

	std::cerr << "Added endpoint " << spec.hostname << ":" << spec.port 
		  << " of type " << spec.type << std::endl;

    }

    // Stop method, remove the mapping.
    virtual void stop() { 

	deliv.remove_endpoint(spec.hostname, spec.port, spec.type);
	std::cerr << "Removed endpoint " << spec.hostname << ":" 
		  << spec.port << std::endl;

    }

};

#endif


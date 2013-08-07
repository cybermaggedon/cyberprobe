
////////////////////////////////////////////////////////////////////////////
//
// ENDPOINT RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef ENDPOINT_H
#define ENDPOINT_H

// An endpoint, describes where to send stuff.
class endpoint_spec : public specification {
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

    // Hash is form host:port.
    virtual std::string get_hash() const { 
	std::ostringstream buf;
	buf << hostname << ":" << port << ":" << type;
	return buf.str();
    }

};

// Endpoint resource.  The endpoint resources are just instantiated as
// changes to the endpoint list in the delivery engine.
class endpoint : public resource {
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


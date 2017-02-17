
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
    std::string hostname;       // Hostname or IP address.
    unsigned short port;        // Port number.
    std::string type;           // One of: etsi, nhis.
    std::string transport;	// One of: tcp, tls.
    
    // Parameters for TLS.
    std::string certificate_file;
    std::string key_file;
    std::string trusted_ca_file;

    // Constructors.
    endpoint_spec() {}
    endpoint_spec(const std::string& hostname, unsigned short port,
		  const std::string& type, const std::string& transport,
		  const std::string& cert, const std::string& key,
		  const std::string& trusted_ca) {
	this->hostname = hostname; this->port = port; this->type = type;
	this->transport = transport; this->certificate_file = cert;
	this->key_file = key; this->trusted_ca_file = trusted_ca;
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

	buf << " " << hostname << ":" << port << ":" << type
	    << certificate_file << ":" << key_file << ":"
	    << trusted_ca_file;
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

	std::map<std::string, std::string> params;
	if (spec.transport == "tls") {
	    params["certificate"] = spec.certificate_file;
	    params["key"] = spec.key_file;
	    params["chain"] = spec.trusted_ca_file;
	}

	deliv.add_endpoint(spec.hostname, spec.port, spec.type,
			   spec.transport, params);

	std::cerr << "Added endpoint " << spec.hostname << ":" << spec.port 
		  << " of type " << spec.type
		  << " with transport " << spec.transport << std::endl;

    }

    // Stop method, remove the mapping.
    virtual void stop() {
	
	std::map<std::string, std::string> params;
	if (spec.transport == "tls") {
	    params["certificate"] = spec.certificate_file;
	    params["key"] = spec.key_file;
	    params["chain"] = spec.trusted_ca_file;
	}

	deliv.remove_endpoint(spec.hostname, spec.port, spec.type,
			      spec.transport, params);

	std::cerr << "Removed endpoint " << spec.hostname << ":" 
		  << spec.port << std::endl;

    }

};

#endif


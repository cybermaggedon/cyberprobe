
////////////////////////////////////////////////////////////////////////////
//
// ENDPOINT RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef ENDPOINT_H
#define ENDPOINT_H

namespace endpoint {

    // An endpoint, describes where to send stuff.
    class spec : public cybermon::specification {
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
        spec() {}
        spec(const std::string& hostname, unsigned short port,
             const std::string& type, const std::string& transport,
             const std::string& cert, const std::string& key,
             const std::string& trusted_ca) {
            this->hostname = hostname; this->port = port; this->type = type;
            this->transport = transport; this->certificate_file = cert;
            this->key_file = key; this->trusted_ca_file = trusted_ca;
        }

        // Hash is form <space> + host:port.
        virtual std::string get_hash() const;

    };

    // Endpoint resource.  The endpoint resources are just instantiated as
    // changes to the endpoint list in the delivery engine.
    class endpoint : public cybermon::resource {
    private:

        // Spec.
        const spec& sp;

        // Delivery engine reference.
        delivery& deliv;

    public:

        // Constructor.
        endpoint(const spec& sp, delivery& d) : 
            sp(sp), deliv(d) { }

        // Start method, change the delivery engine mapping.
        virtual void start() { 

            std::map<std::string, std::string> params;
            if (sp.transport == "tls") {
                params["certificate"] = sp.certificate_file;
                params["key"] = sp.key_file;
                params["chain"] = sp.trusted_ca_file;
            }

            deliv.add_endpoint(sp.hostname, sp.port, sp.type,
                               sp.transport, params);

            std::cerr << "Added endpoint " << sp.hostname << ":" << sp.port 
                      << " of type " << sp.type
                      << " with transport " << sp.transport << std::endl;

        }

        // Stop method, remove the mapping.
        virtual void stop() {
	
            std::map<std::string, std::string> params;
            if (sp.transport == "tls") {
                params["certificate"] = sp.certificate_file;
                params["key"] = sp.key_file;
                params["chain"] = sp.trusted_ca_file;
            }

            deliv.remove_endpoint(sp.hostname, sp.port, sp.type,
                                  sp.transport, params);

            std::cerr << "Removed endpoint " << sp.hostname << ":" 
                      << sp.port << std::endl;

        }

    };

};

#endif


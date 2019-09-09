
////////////////////////////////////////////////////////////////////////////
//
// ENDPOINT RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef ENDPOINT_H
#define ENDPOINT_H

#include <string>

#include <cyberprobe/resources/specification.h>
#include <cyberprobe/resources/resource.h>
#include <nlohmann/json.h>

namespace cyberprobe {

namespace probe {

class delivery;

namespace endpoint {

    using json = nlohmann::json;

    // An endpoint, describes where to send stuff.
    class spec : public cyberprobe::resources::specification {
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

        bool operator<(const spec& i) const {

            if (hostname < i.hostname)
                return true;
            else if (hostname > i.hostname) return false;

            if (port < i.port)
                return true;
            else if (port > i.port) return false;

            if (type < i.type)
                return true;
            else if (type > i.type) return false;

            if (transport < i.transport)
                return true;
            else if (transport > i.transport) return false;

            if (certificate_file < i.certificate_file)
                return true;
            else if (certificate_file > i.certificate_file) return false;

            if (key_file < i.key_file)
                return true;
            else if (key_file > i.key_file) return false;

            if (trusted_ca_file < i.trusted_ca_file)
                return true;

            return false;

        }
        
    };

    // Endpoint resource.  The endpoint resources are just instantiated as
    // changes to the endpoint list in the delivery engine.
    class endpoint : public cyberprobe::resources::resource {
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
        virtual void start();

        // Stop method, remove the mapping.
        virtual void stop();

    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

}

}

}

#endif


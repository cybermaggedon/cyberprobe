
#include <string>

#include <cyberprobe/probe/endpoint.h>
#include <cyberprobe/probe/delivery.h>
#include <nlohmann/json.h>

namespace cyberprobe {

namespace probe {

namespace endpoint {

    void to_json(json& j, const spec& s) {
        j = json{{"hostname", s.hostname},
                 {"port", s.port},
                 {"type", s.type},
                 {"transport", s.transport}
        };
        if (s.transport == "tls") {
            j["certificate"] = s.certificate_file;
            j["key"] = s.key_file;
            j["trusted-ca"] = s.trusted_ca_file;
        };
    }

    void from_json(const json& j, spec& s) {
        j.at("hostname").get_to(s.hostname);
        j.at("port").get_to(s.port);
        j.at("type").get_to(s.type);
        try {
            j.at("transport").get_to(s.transport);
        } catch (...) {
            s.transport = "tcp";
        }
        if (s.transport == "tls") {
            j.at("certificate").get_to(s.certificate_file);
            j.at("key").get_to(s.key_file);
            j.at("trusted-ca").get_to(s.trusted_ca_file);
        }
    }

    std::string spec::get_hash() const {

        // See that space before the hash?  It means that endpoint
        // hashes are "less than" other hashes, which means they are at the
        // front of the set.  This means endpoints are started before
        // targets.
        
        // The end result of that, is that we know endpoints will be
        // configured before targets are added to the delivery engine,
        // which means that 'target up' messages will be sent on targets
        // configured in the config file.
        
        json j = *this;
        return " " + j.dump();
        
    }

    void endpoint::start() { 

        deliv.add_endpoint(sp);

        std::cerr << "Added endpoint " << sp.hostname << ":" << sp.port 
                  << " of type " << sp.type
                  << " with transport " << sp.transport << std::endl;

    }

    void endpoint::stop() {
	
        deliv.remove_endpoint(sp);

        std::cerr << "Removed endpoint " << sp.hostname << ":" 
                  << sp.port << std::endl;

    }

}

}

}


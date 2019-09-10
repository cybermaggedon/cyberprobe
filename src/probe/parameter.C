
#include <cyberprobe/probe/delivery.h>
#include <cyberprobe/probe/parameter.h>

namespace cyberprobe {

namespace probe   {

namespace parameter {

    void to_json(json& j, const spec& s) {
        j = json{{"key", s.key},
                 {"value", s.val}};
    }
    
    void from_json(const json& j, spec& s) {
        j.at("key").get_to(s.key);
        j.at("value").get_to(s.val);
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
        return "   " + j.dump();

    }
    
    // Start method, change the delivery engine mapping.
    void parameter::start() { 
        deliv.add_parameter(sp);
        std::cerr << "Added parameter " << sp.key << "=" << sp.val 
                  << std::endl;
    }

    // Stop method, remove the mapping.
    void parameter::stop() { 
        deliv.remove_parameter(sp);
        std::cerr << "Removed parameter " << sp.key << "=" << sp.val 
                  << std::endl;
    }

};

}

}


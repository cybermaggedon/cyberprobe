
////////////////////////////////////////////////////////////////////////////
//
// PARAMETER RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef PARAMETER_H
#define PARAMETER_H

#include <cybermon/resource.h>

#include "delivery.h"
#include "json.h"

namespace parameter {

    using json = nlohmann::json;

    // A paramter, represents a key/val pair.
    class spec : public cybermon::specification {
    public:

        // Type is 'target'.
        virtual std::string get_type() const { return "parameter"; }

        // key/val pair
        std::string key;
        std::string val;

        // Constructors.
        spec() {}

        spec(const std::string& key, const std::string& val) { 
            this->key = key; this->val = val;
        }

        // Hash is form key=val
        virtual std::string get_hash() const;

    };

    // Parameter resource.  Just instantiated as changes to the delivery engine.
    class parameter : public cybermon::resource {
    private:

        // Spec.
        const spec& sp;

        // Delivery engine reference.
        delivery& deliv;

    public:

        // Constructor.
        parameter(const spec& sp, delivery& d) : 
            sp(sp), deliv(d) { }

        // Start method, change the delivery engine mapping.
        virtual void start() { 
            deliv.add_parameter(sp.key, sp.val);
            std::cerr << "Added parameter " << sp.key << "=" << sp.val 
                      << std::endl;
        }

        // Stop method, remove the mapping.
        virtual void stop() { 
            deliv.remove_parameter(sp.key);
            std::cerr << "Removed parameter " << sp.key << "=" << sp.val 
                      << std::endl;
        }

    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

};

#endif


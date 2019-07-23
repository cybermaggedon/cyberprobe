
////////////////////////////////////////////////////////////////////////////
//
// PARAMETER RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef PARAMETER_H
#define PARAMETER_H

#include <cybermon/resource.h>

#include "json.h"

class delivery;

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
        virtual void start();

        // Stop method, remove the mapping.
        virtual void stop();

    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

};

#endif


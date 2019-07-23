
////////////////////////////////////////////////////////////////////////////
//
// INTERFACE RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef INTERFACE_H
#define INTERFACE_H

#include <cybermon/specification.h>
#include <cybermon/resource.h>

#include "capture.h"
#include "json.h"

#include <string>

class delivery;

namespace interface {

    using json = nlohmann::json;

    // An interface specification
    class spec : public cybermon::specification {
    public:

        // Type is 'iface'
        virtual std::string get_type() const { return "iface"; }

        // Interface name e.g. eth0
        std::string ifa;

        // Capture filter.
        std::string filter;

        // Delay
        float delay;

        // Constructors.
        spec() {}
        spec(const std::string& ifa) { this->ifa = ifa; delay = 0.0; }

        // Hash is <interface>:<filter>:<delay>
        virtual std::string get_hash() const;

        bool operator<(const spec& i) const {

            if (ifa < i.ifa)
                return true;
            else if (ifa > i.ifa) return false;

            if (filter < i.filter)
                return true;
            else if (filter > i.filter) return false;

            if (delay < i.delay)
                return true;

            return false;

        }
        
    };

    // An interface resources, basically wraps the 'cap' class in a thread
    // which can started and stopped.
    class iface : public cybermon::resource {
    private:

        // Specification.
        const spec& sp;

        // Reference to the delivery engine.
        delivery& deliv;

    public:

        // Constructor.
        iface(const spec& sp, delivery& d) : 
            sp(sp), deliv(d) {}

        // Start method.
        virtual void start();

        // Stop method.
        virtual void stop();

    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

};

#endif


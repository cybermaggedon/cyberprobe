
////////////////////////////////////////////////////////////////////////////
//
// INTERFACE RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef INTERFACE_H
#define INTERFACE_H

#include <cyberprobe/resources/specification.h>
#include <cyberprobe/resources/resource.h>
#include <cyberprobe/probe/capture.h>
#include <nlohmann/json.h>

#include <string>

namespace cyberprobe {

namespace probe {

class delivery;

namespace interface {

    using json = nlohmann::json;

    // An interface specification
    class spec : public cyberprobe::resources::specification {
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
    class iface : public cyberprobe::resources::resource {
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

}

}

}

#endif


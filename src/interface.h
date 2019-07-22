
////////////////////////////////////////////////////////////////////////////
//
// INTERFACE RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef INTERFACE_H
#define INTERFACE_H

#include <cybermon/specification.h>
#include <cybermon/resource.h>
#include <delivery.h>

#include "capture.h"
#include "json.h"

#include <string>

using json = nlohmann::json;

namespace interface {

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
        virtual void start() { 

            deliv.add_interface(sp.ifa, sp.filter, sp.delay);

            std::cerr << "Capture on interface " << sp.ifa << " started."
                      << std::endl;
            if (sp.filter != "")
                std::cerr << "  filter: " << sp.filter << std::endl;
            if (sp.delay != 0.0)
                std::cerr << "  delay: " << sp.delay << std::endl;

        }

        // Stop method.
        virtual void stop() { 
            deliv.remove_interface(sp.ifa, sp.filter, sp.delay);
            std::cerr << "Capture on interface " << sp.ifa << " stopped."
                      << std::endl;
        }

    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

};

#endif


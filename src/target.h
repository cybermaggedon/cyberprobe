
////////////////////////////////////////////////////////////////////////////
//
// TARGET RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef TARGET_H
#define TARGET_H

#include <cybermon/socket.h>
#include <cybermon/specification.h>
#include <cybermon/resource.h>

#include "delivery.h"
#include "json.h"

using json = nlohmann::json;

namespace target {

    // A target specification: Maps an IP address to a device ID.
    class spec : public cybermon::specification {
    public:

        // Type is 'target'.
        virtual std::string get_type() const { return "target"; }

        // Device
        std::string device;

        // Network
        std::string network;
    
        // IP addresses
        tcpip::ip4_address addr;
        tcpip::ip6_address addr6;

        // Mask
        unsigned int mask;

        enum { IPv4, IPv6} universe;

        // Constructors.
        spec() { universe = IPv4; }

        // Set IPv4 address match.
        void set_ipv4(const std::string& device, const std::string& network,
                      const tcpip::ip4_address& addr,
                      unsigned int mask = 32) {
            this->network = network;
            this->device = device; this->addr = addr; universe = IPv4; 
            this->mask = mask;
        }

        // Set IPv6 address match.
        void set_ipv6(const std::string& device,
                      const std::string& network,
                      const tcpip::ip6_address& addr,
                      unsigned int mask = 128) {
            this->device = device;
            this->network = network;
            this->addr6 = addr; universe = IPv6;
            this->mask = mask;
        }

        // Hash is form ipaddr:device.
        virtual std::string get_hash() const { 
            std::ostringstream buf;
	
            if (universe == IPv4)
                buf << "IPv4:" << addr;
            else
                buf << "IPv6:" << addr6;

            buf << ":" << network;

            buf << ":" << device;

            buf << ":" << mask;

            return buf.str();
        }

    };

    // Target resource.  The target resources are just instantiated as
    // changes to the target map in the delivery engine.
    class target : public cybermon::resource {
    private:

        // Spec.
        const spec& sp;

        // Delivery engine reference.
        delivery& deliv;

    public:

        // Constructor.
        target(const spec& sp, delivery& d) : 
            sp(sp), deliv(d) { }

        // Start method, change the delivery engine mapping.
        virtual void start() { 

            std::string txt;
            if (sp.universe == spec::IPv4) {
                deliv.add_target(sp.addr, sp.mask, sp.device,
                                 sp.network);
                sp.addr.to_string(txt);
            } else {
                deliv.add_target(sp.addr6, sp.mask, sp.device,
                                 sp.network);
                sp.addr6.to_string(txt);
            }

            std::cerr << "Added target " << txt << "/" << sp.mask
                      << " -> " 
                      << sp.device << "." << std::endl;

        }

        // Stop method, remove the mapping.
        virtual void stop() { 

            std::string txt;
            if (sp.universe == spec::IPv4) {
                deliv.remove_target(sp.addr, sp.mask);
                sp.addr.to_string(txt);
            } else {
                deliv.remove_target(sp.addr6, sp.mask);
                sp.addr6.to_string(txt);
            }

            std::cerr << "Removed target " << txt << "/" << sp.mask
                      << " -> " 
                      << sp.device << "." << std::endl;
        }

    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

};

#endif


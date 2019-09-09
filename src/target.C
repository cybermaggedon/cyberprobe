
#include <cyberprobe/resources/specification.h>
#include <cyberprobe/resources/resource.h>
#include <cyberprobe/network/socket.h>

#include <cyberprobe/probe/target.h>
#include <cyberprobe/probe/delivery.h>
#include <nlohmann/json.h>
    
using json = nlohmann::json;

namespace cyberprobe {

namespace probe {
        
namespace target {

    void to_json(json& j, const spec& s) {
        std::string addr;
        std::string cls;
        if (s.universe == s.IPv6) {
            s.addr6.to_string(addr);
            if (s.mask != 128)
                addr += "/" + std::to_string(s.mask);
            cls = "ipv6";
        } else if (s.universe == s.IPv4) {
            s.addr.to_string(addr);
            if (s.mask != 32)
                addr += "/" + std::to_string(s.mask);
            cls = "ipv4";
        } else
        throw std::runtime_error("Address not IPv6 or IPv4");
        j = json{{"device", s.device},
                 {"network", s.network},
                 {"address", addr}, {"class", cls}
        };
    }

    void from_json(const json& j, spec& s) {
        
        j.at("device").get_to(s.device);
        
        try {
            j.at("network").get_to(s.network);
        } catch (...) {
            s.network = "";
        }
        
        std::string cls;
        try {
            j.at("class").get_to(cls);
        } catch (...) {
            cls = "ipv4";
        }
        
        if (cls != "ipv4" && cls != "ipv6")
            throw std::runtime_error("Class must be ipv4 or ipv6");

        std::string address;
        j.at("address").get_to(address);
        
        int pos = address.find("/");
        std::string mstr = address.substr(pos + 1);
        if (pos != -1) {
            s.mask = std::stoi(mstr);
            address = address.substr(0, pos);
        } else if (cls == "ipv4")
            s.mask = 32;
        else // IPv6 case
            s.mask = 128;
        
        if (cls == "ipv4") {
            // Convert string to an IPv4 address.
            tcpip::ip4_address addr;
            s.addr.from_string(address);
            s.universe = s.IPv4;
            
        } else {
            // Convert string to an IPv6 address.
            tcpip::ip6_address addr;
            s.addr6.from_string(address);
            s.universe = s.IPv6;

        }
	
    }

        // Start method, change the delivery engine mapping.
    void target::start() { 

        std::string txt;

        deliv.add_target(sp);
        if (sp.universe == spec::IPv4)
            sp.addr.to_string(txt);
        else
            sp.addr6.to_string(txt);
        
        std::cerr << "Added target " << txt << "/" << sp.mask
                  << " -> " 
                  << sp.device << "." << std::endl;
        
    }

    void target::stop() { 

        std::string txt;

        if (sp.universe == spec::IPv4)
            sp.addr.to_string(txt);
        else
            sp.addr6.to_string(txt);

        deliv.remove_target(sp);
        
        std::cerr << "Removed target " << txt << "/" << sp.mask
                  << " -> " 
                  << sp.device << "." << std::endl;

    }

}

}

}


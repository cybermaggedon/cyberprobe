
#include "configuration.h"
#include "interface.h"
#include "target.h"
#include "endpoint.h"
#include "parameter.h"
#include "snort_alert.h"
#include "control.h"
#include "json.h"

using json = nlohmann::json;

void to_json(json& j, const iface_spec& s) {
    j = json{{"interface", s.ifa}, {"filter", s.filter},
             {"delay", s.delay}};
}

void from_json(const json& j, iface_spec& s) {
    j.at("interface").get_to(s.ifa);
    try {
        j.at("filter").get_to(s.filter);
    } catch (...) {
        s.filter = "";
    }
    try {
        j.at("delay").get_to(s.delay);
    } catch (...) {
        s.delay = 0.0;
    }
}

void to_json(json& j, const target_spec& s) {
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

void from_json(const json& j, target_spec& s) {

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

    int mask;

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

    } else {

        // Convert string to an IPv6 address.
        tcpip::ip6_address addr;
        s.addr6.from_string(address);

    }
			
}

// Read the configuration file, and convert into a list of specifications.
void config_manager::read(const std::string& file, 
			  std::list<cybermon::specification*>& lst)
{

    try {

	// Read the file.
        // FIXME: json class supports deserialisation from stream.
	std::string data;
	get_file(file, data);

	// Parse XML
        auto config = json::parse(data);

	/////////////////////////////////////////////////////////////
	// Scan the interfaces block.
	/////////////////////////////////////////////////////////////

        auto interfaces_j = config["interfaces"];
/*
        for(json::iterator it = interfaces_j.begin(); it != interfaces_j.end();
            it++) {
            iface_spec* sp = new iface_spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }
*/
	/////////////////////////////////////////////////////////////
	// Scan the targets block.
	/////////////////////////////////////////////////////////////

        auto targets_j = config["targets"];

        for(json::iterator it = targets_j.begin(); it != targets_j.end();
            it++) {
            target_spec* sp = new target_spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }
        
#ifdef BROKEN

	try {

	    xml::element& t_elt = dec.root.locate("targets");

	    for(std::list<xml::element>::iterator it = t_elt.children.begin();
		it != t_elt.children.end();
		it++) {

		// For each target element, get the device, address and optional
		// class attributes.
		if (it->name == "target") {

                    std::string device;

                    // Get device attributes
		    if (it->attributes.find("device") != it->attributes.end())
                        device = it->attributes["device"];
                    
                    // Can be called liid as well.
                    if (it->attributes.find("liid") != it->attributes.end())
                        device = it->attributes["liid"];

                    if (device == "") {
			std::cerr
			    << "target element without 'device' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }
		    
		    if (it->attributes.find("address") ==
			it->attributes.end()) {
			std::cerr
			    << "target element without 'address' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }

		    std::string ip = it->attributes["address"];
		    std::string cs = it->attributes["class"];
		    std::string network = it->attributes["network"];

		    if (cs != "ipv6") {
			
			// IPv4 case
			int mask = 32;

			int pos = ip.find("/");
			if (pos != -1) {
			    std::string m = ip.substr(pos + 1);
			    std::istringstream buf(m);
			    buf >> mask;
			    ip = ip.substr(0, pos);
			}

			// Convert string to an IPv4 address.
			tcpip::ip4_address addr;
			addr.from_string(ip);
			
			// Create target specification.
			target_spec* sp = new target_spec;
			sp->set_ipv4(device, network, addr, mask);
			lst.push_back(sp);
			
		    } else {
			
			// IPv6 case
			int mask = 128;

			int pos = ip.find("/");
			if (pos != -1) {
			    std::string m = ip.substr(pos + 1);
			    std::istringstream buf(m);
			    buf >> mask;
			    ip = ip.substr(0, pos);
			}

			// Convert string to an IPv6 address.
			tcpip::ip6_address addr;
			addr.from_string(ip);
			
			// Create target specfication.
			target_spec* sp = new target_spec;
			sp->set_ipv6(device, network, addr, mask);
			lst.push_back(sp);
			
		    }

		    continue;

		}

	    }

	} catch (std::exception& e) {
	    
	    std::cerr << "Error parsing targets: " << e.what() << std::endl;

	}

	/////////////////////////////////////////////////////////////
	// Scan the endpoints block.
	/////////////////////////////////////////////////////////////

	try {

	    xml::element& e_elt = dec.root.locate("endpoints");

	    for(std::list<xml::element>::iterator it = e_elt.children.begin();
		it != e_elt.children.end();
		it++) {
		
		// For each endpoint attribute, get hostname, port and type
		// attributes.
		if (it->name == "endpoint") {
		    
		    // All these attributes are mandatory.
		    if (it->attributes.find("hostname") ==
			it->attributes.end()) {
			std::cerr
			    << "endpoint element without 'hostname' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }
		    if (it->attributes.find("port") == it->attributes.end()) {
			std::cerr
			    << "endpoint element without 'port' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }
		    if (it->attributes.find("type") == it->attributes.end()) {
			std::cerr
			    << "endpoint element without 'type' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }

		    // Get the attributes.
		    std::string hostname = it->attributes["hostname"];
		    std::string type = it->attributes["type"];
		    std::string transport = it->attributes["transport"];

		    // Transport defaults to TCP.
		    if (transport == "") transport = "tcp";

		    if (transport == "tls") {
			if (it->attributes.find("certificate") ==
			    it->attributes.end()) {
			    std::cerr
				<< "TLS endpoint element without 'certficate' "
				<< "attributed, ignored"
				<< std::endl;
			    continue;
			}
			if (it->attributes.find("key") ==
			    it->attributes.end()) {
			    std::cerr
				<< "TLS endpoint element without 'key' "
				<< "attributed, ignored"
				<< std::endl;
			    continue;
			}
			if (it->attributes.find("trusted-ca") ==
			    it->attributes.end()) {
			    std::cerr
				<< "TLS endpoint element without 'trusted-ca' "
				<< "attributed, ignored"
				<< std::endl;
			    continue;
			}
		    }

		    // Optional attributes
		    std::string cert = it->attributes["certificate"];
		    std::string key = it->attributes["key"];
		    std::string trusted_ca = it->attributes["trusted-ca"];

		    // Scan port string into an integer.
		    std::istringstream buf(it->attributes["port"]);
		    int port;
		    buf >> port;
		
		    // Create an endpoint specification.
		    cybermon::specification* sp = 
                        new endpoint_spec(hostname, port, type, transport,
                                          cert, key, trusted_ca);
		    lst.push_back(sp);
		    continue;

		}
		
	    }

	} catch (std::exception& e) {

	    std::cerr << "Error parsing endpoints: " << e.what() << std::endl;

	}

	/////////////////////////////////////////////////////////////
	// Scan the parameters block.
	/////////////////////////////////////////////////////////////

	try {

	    xml::element& p_elt = dec.root.locate("parameters");
	    
	    for(std::list<xml::element>::iterator it = p_elt.children.begin();
		it != p_elt.children.end();
		it++) {
		
		// For each parameter element, get key and value attributes.
		// attributes.
		if (it->name == "parameter") {
		    
		    // Both attributes are mandatory.
		    if (it->attributes.find("key") == it->attributes.end()) {
			std::cerr
			    << "parameter element without 'key' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }
		    if (it->attributes.find("value") == it->attributes.end()) {
			std::cerr
			    << "parameter element without 'vakue' attribute, "
			    << "ignored"
			    << std::endl;
			continue;
		    }
		    
		    // Get attributes.
		    std::string key = it->attributes["key"];
		    std::string val = it->attributes["value"];
		    
		    // Create and return a specfication.
		    cybermon::specification* sp = new parameter_spec(key, val);
		    lst.push_back(sp);
		    
		    continue;

		}

	    }
	    
	} catch (std::exception& e) {

//	    std::cerr << "Error parsing parameters: " << e.what() << std::endl;
	    // Silently ignore.

	}

	/////////////////////////////////////////////////////////////
	// Control parameters.
	/////////////////////////////////////////////////////////////

	try {

	    xml::element& s_elt = dec.root.locate("control");
	    
	    if (s_elt.attributes.find("port") != s_elt.attributes.end() &&
		s_elt.attributes.find("username") != s_elt.attributes.end() &&
		s_elt.attributes.find("password") != s_elt.attributes.end()) {

		std::istringstream buf(s_elt.attributes["port"]);
		int port;
		buf >> port;
		std::string username = s_elt.attributes["username"];
		std::string password = s_elt.attributes["password"];

		// Create alerter
		control::spec* sp = 
		    new control::spec(port, username, password);

		lst.push_back(sp);

	    }

	} catch (std::exception& e) {

	    // Silently ignore.

	}

	/////////////////////////////////////////////////////////////
	// Scan the snort alert receiver
	/////////////////////////////////////////////////////////////

	try {

	    xml::element& s_elt = dec.root.locate("snort_alert");
	    
	    if (s_elt.attributes.find("socket") != s_elt.attributes.end() &&
		s_elt.attributes.find("duration") != s_elt.attributes.end()) {

		std::string socket = s_elt.attributes["socket"];
		std::istringstream buf(s_elt.attributes["duration"]);
		int duration;
		buf >> duration;

		// Create alerter
		snort_alerter_spec* sp = 
		    new snort_alerter_spec(socket, duration);

		lst.push_back(sp);

	    }

	} catch (std::exception& e) {

	    // Silently ignore.

	}

#endif

    } catch (std::exception& e) {
	    
	std::cerr << "Error parsing configuration file: " << e.what() 
		  << std::endl;

    }

}

// Create resources from specifications.
cybermon::resource* config_manager::create(cybermon::specification& spec)
{
    
    // Interface.
    if (spec.get_type() == "iface") {
	iface_spec& s = dynamic_cast<iface_spec&>(spec);
	return new iface(s, deliv);
    }

    // Target.
    if (spec.get_type() == "target") {
	target_spec& s = dynamic_cast<target_spec&>(spec);
	return new target(s, deliv);
    }

    // Endpoint.
    if (spec.get_type() == "endpoint") {
	endpoint_spec& s = dynamic_cast<endpoint_spec&>(spec);
	return new endpoint(s, deliv);
    }

    // Parameter.
    if (spec.get_type() == "parameter") {
	parameter_spec& s = dynamic_cast<parameter_spec&>(spec);
	return new parameter(s, deliv);
    }

    // Snort alerter.
    if (spec.get_type() == "snort_alerter") {
	snort_alerter_spec& s = dynamic_cast<snort_alerter_spec&>(spec);
	return new snort_alerter(s, deliv);
    }

    // Control.
    if (spec.get_type() == "control") {
	control::spec& s = dynamic_cast<control::spec&>(spec);
	return new control::service(s, deliv);
    }

    // This REALLY shouldn't happen, because config_manager::read only
    // creates the above 4 resources types.

    // Also, there are only 4 resources types in the code.

    throw std::runtime_error("Shouldn't be here!  Wrong resource type.");

}



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
        std::cout << "IPv4 addr:" << address << std::endl;
        s.universe = s.IPv4;
        
    } else {

        // Convert string to an IPv6 address.
        tcpip::ip6_address addr;
        s.addr6.from_string(address);
        std::cout << "IPv6 addr:" << address << std::endl;
        s.universe = s.IPv6;

    }
			
}

void to_json(json& j, const endpoint_spec& s) {
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

void from_json(const json& j, endpoint_spec& s) {
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

std::string endpoint_spec::get_hash() const {

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

void to_json(json& j, const parameter_spec& s) {
    j = json{{"key", s.key},
             {"value", s.val}};
}

void from_json(const json& j, parameter_spec& s) {
    j.at("key").get_to(s.key);
    j.at("value").get_to(s.val);
}

std::string parameter_spec::get_hash() const {

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

namespace control {

    void to_json(json& j, const spec& s) {
        j = json{{"port", s.port},
                 {"username", s.username},
                 {"password", s.password}};
    }
    
    void from_json(const json& j, spec& s) {
        j.at("port").get_to(s.port);
        j.at("username").get_to(s.username);
        j.at("password").get_to(s.password);
    }

};

namespace snort_alert {

    void to_json(json& j, const spec& s) {
        j = json{{"path", s.path}, {"duration", s.duration}};
    }

    void from_json(const json& j, spec& s) {
        j.at("path").get_to(s.path);
        j.at("duration").get_to(s.duration);
    }

    std::string spec::get_hash() const { 
        json j = *this;
        return " " + j.dump();            
    }

};

// Read the configuration file, and convert into a list of specifications.
void config_manager::read(const std::string& file, 
			  std::list<cybermon::specification*>& lst)
{

    try {

	// Read the file.
        // FIXME: json class supports deserialisation from stream.
	std::string data;
	get_file(file, data);

	// Parse config file
        auto config = json::parse(data);

	/////////////////////////////////////////////////////////////
	// Scan the interfaces block.
	/////////////////////////////////////////////////////////////

        auto interfaces_j = config["interfaces"];

        for(json::iterator it = interfaces_j.begin(); it != interfaces_j.end();
            it++) {
            iface_spec* sp = new iface_spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }

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

	/////////////////////////////////////////////////////////////
	// Scan the endpoints block.
	/////////////////////////////////////////////////////////////

        auto endpoints_j = config["endpoints"];

        for(json::iterator it = endpoints_j.begin(); it != endpoints_j.end();
            it++) {
            endpoint_spec* sp = new endpoint_spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }

	/////////////////////////////////////////////////////////////
	// Scan the parameters block.
	/////////////////////////////////////////////////////////////

        auto parameters_j = config["parameters"];

        for(json::iterator it = parameters_j.begin(); it != parameters_j.end();
            it++) {
            parameter_spec* sp =
                new parameter_spec(it.key(),
                                   it.value().get<std::string>());
            lst.push_back(sp);
        }        

	/////////////////////////////////////////////////////////////
	// Scan the controls block.
	/////////////////////////////////////////////////////////////

        auto control_j = config["controls"];

        for(json::iterator it = control_j.begin(); it != control_j.end();
            it++) {
            control::spec* sp = new control::spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }        

	/////////////////////////////////////////////////////////////
	// Scan the snort alert receiver
	/////////////////////////////////////////////////////////////

        auto snort_alerter_j = config["snort-alerters"];

        for(json::iterator it = snort_alerter_j.begin();
            it != snort_alerter_j.end();
            it++) {
            snort_alert::spec* sp = new snort_alert::spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }        

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
        snort_alert::spec& s = dynamic_cast<snort_alert::spec&>(spec);
	return new snort_alert::snort_alerter(s, deliv);
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


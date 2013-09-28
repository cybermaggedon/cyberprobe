
#include "configuration.h"
#include "xml.h"
#include "interface.h"
#include "target.h"
#include "endpoint.h"
#include "parameter.h"
#include "snort_alert.h"
#include "control.h"

// Read the configuration file, and convert into a list of specifications.
void config_manager::read(const std::string& file, 
			  std::list<specification*>& lst)
{

    try {

	// Read the file.
	std::string data;
	get_file(file, data);

	// Parse XML
	xml::decoder dec;
	dec.parse(data);

	/////////////////////////////////////////////////////////////
	// Scan the interfaces block.
	/////////////////////////////////////////////////////////////

	xml::element& i_elt = dec.root.locate("interfaces");

	for(std::list<xml::element>::iterator it = i_elt.children.begin();
	    it != i_elt.children.end();
	    it++) {

	    // For each interface element get the name attribute.
	    if (it->name == "interface") {
		
		if (it->attributes.find("name") != it->attributes.end()) {
		    
		    // Create an interface specification for each element.
		    iface_spec* sp = new iface_spec(it->attributes["name"]);

		    // Get the filter attribute, if exists.
		    if (it->attributes.find("filter") != it->attributes.end())
			sp->filter = it->attributes["filter"];

		    // Get the delay attribute, if exists.
		    if (it->attributes.find("delay") != it->attributes.end()) {
			// Scan port string into a float.
			std::istringstream buf(it->attributes["delay"]);
			buf >> sp->delay;
		    }

		    lst.push_back(sp);

		}

	    }

	}

	/////////////////////////////////////////////////////////////
	// Scan the targets block.
	/////////////////////////////////////////////////////////////

	xml::element& t_elt = dec.root.locate("targets");

	for(std::list<xml::element>::iterator it = t_elt.children.begin();
	    it != t_elt.children.end();
	    it++) {

	    // For each target element, get the liid, address and optional
	    // class attributes.
	    if (it->name == "target") {
		
		// Bail if liid or address aren't specified.
		if (it->attributes.find("liid") == it->attributes.end())
		    continue;

		if (it->attributes.find("address") == it->attributes.end())
		    continue;

		std::string ip = it->attributes["address"];
		std::string liid = it->attributes["liid"];
		std::string cs = it->attributes["class"];

		if (cs != "ipv6") {

		    // IPv4 case

		    // Convert string to an IPv4 address.
		    tcpip::ip4_address addr;
		    addr.from_string(ip);

		    // Create target specification.
		    target_spec* sp = new target_spec;
		    sp->set_ipv4(liid, addr);
		    lst.push_back(sp);

		} else {

		    // IPv6 case

		    // Convert string to an IPv6 address.
		    tcpip::ip6_address addr;
		    addr.from_string(ip);

		    // Create target specfication.
		    target_spec* sp = new target_spec;
		    sp->set_ipv6(liid, addr);
		    lst.push_back(sp);

		}

		continue;

	    }

	}

	/////////////////////////////////////////////////////////////
	// Scan the endpoints block.
	/////////////////////////////////////////////////////////////

	xml::element& e_elt = dec.root.locate("endpoints");

	for(std::list<xml::element>::iterator it = e_elt.children.begin();
	    it != e_elt.children.end();
	    it++) {

	    // For each endpoint attribute, get hostname, port and type
	    // attributes.
	    if (it->name == "endpoint") {
		
		// All three attributes are mandatory.
		if (it->attributes.find("hostname") == it->attributes.end())
		    continue;
		if (it->attributes.find("port") == it->attributes.end())
		    continue;
		if (it->attributes.find("type") == it->attributes.end())
		    continue;

		// Get the attributes.
		std::string hostname = it->attributes["hostname"];
		std::string type = it->attributes["type"];

		// Scan port string into an integer.
		std::istringstream buf(it->attributes["port"]);
		int port;
		buf >> port;

		// Create an endpoint specification.
		specification* sp = new endpoint_spec(hostname, port, type);
		lst.push_back(sp);
		continue;

	    }

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
		    if (it->attributes.find("key") == it->attributes.end())
			continue;
		    if (it->attributes.find("value") == it->attributes.end())
			continue;
		    
		    // Get attributes.
		    std::string key = it->attributes["key"];
		    std::string val = it->attributes["value"];
		    
		    // Create and return a specfication.
		    specification* sp = new parameter_spec(key, val);
		    lst.push_back(sp);
		    
		    continue;

		}

	    }
	    
	} catch (...) {

	    // Silently ignore broken configuration.

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

	} catch (...) {
	    
	    // Silently ignore broken configuration.

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

	} catch (...) {
	    
	    // Silently ignore broken configuration.

	}

    } catch (...) {
	    
	// Silently ignore broken configuration.

    }

}

// Create resources from specifications.
resource* config_manager::create(specification& spec)
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


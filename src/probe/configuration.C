
#include <cyberprobe/probe/configuration.h>
#include <cyberprobe/probe/interface.h>
#include <cyberprobe/probe/target.h>
#include <cyberprobe/probe/endpoint.h>
#include <cyberprobe/probe/parameter.h>
#include <cyberprobe/probe/snort_alert.h>
#include <cyberprobe/probe/control.h>
#include <nlohmann/json.h>

using json = nlohmann::json;

using namespace cyberprobe::probe;
using namespace cyberprobe::resources;

// Read the configuration file, and convert into a list of specifications.
void config_manager::read(const std::string& file, 
			  std::list<specification*>& lst)
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
            interface::spec* sp = new interface::spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }

	/////////////////////////////////////////////////////////////
	// Scan the targets block.
	/////////////////////////////////////////////////////////////

        auto targets_j = config["targets"];

        for(json::iterator it = targets_j.begin(); it != targets_j.end();
            it++) {
            target::spec* sp = new target::spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }

	/////////////////////////////////////////////////////////////
	// Scan the endpoints block.
	/////////////////////////////////////////////////////////////

        auto endpoints_j = config["endpoints"];

        for(json::iterator it = endpoints_j.begin(); it != endpoints_j.end();
            it++) {
            endpoint::spec* sp = new endpoint::spec();
            it->get_to(*sp);
            lst.push_back(sp);
        }

	/////////////////////////////////////////////////////////////
	// Scan the parameters block.
	/////////////////////////////////////////////////////////////

        auto parameters_j = config["parameters"];

        for(json::iterator it = parameters_j.begin(); it != parameters_j.end();
            it++) {
            parameter::spec* sp =
                new parameter::spec(it.key(),
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
resource* config_manager::create(specification& spec)
{
    
    // Interface.
    if (spec.get_type() == "iface") {
        interface::spec& s = dynamic_cast<interface::spec&>(spec);
	return new interface::iface(s, deliv);
    }

    // Target.
    if (spec.get_type() == "target") {
        target::spec& s = dynamic_cast<target::spec&>(spec);
	return new target::target(s, deliv);
    }

    // Endpoint.
    if (spec.get_type() == "endpoint") {
        endpoint::spec& s = dynamic_cast<endpoint::spec&>(spec);
	return new endpoint::endpoint(s, deliv);
    }

    // Parameter.
    if (spec.get_type() == "parameter") {
        parameter::spec& s = dynamic_cast<parameter::spec&>(spec);
	return new parameter::parameter(s, deliv);
    }

    // Snort alerter.
    if (spec.get_type() == "snort_alerter") {
        snort_alert::spec& s = dynamic_cast<snort_alert::spec&>(spec);
	return new snort_alert::snort_alerter(s, deliv);
    }

    // Control.
    if (spec.get_type() == "control") {
        control::spec& s =
            dynamic_cast<control::spec&>(spec);
	return new control::service(s, deliv);
    }

    // This REALLY shouldn't happen, because config_manager::read only
    // creates the above 4 resources types.

    // Also, there are only 4 resources types in the code.

    throw std::runtime_error("Shouldn't be here!  Wrong resource type.");

}


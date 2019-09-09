
#include <iostream>
#include <sstream>
#include <vector>
#include <regex>
#include <iomanip>

#include <cyberprobe/network/socket.h>
#include <cyberprobe/probe/interface.h>
#include <cyberprobe/probe/endpoint.h>
#include <cyberprobe/probe/target.h>
#include <cyberprobe/probe/parameter.h>
#include <cyberprobe/util/readline.h>

#include <nlohmann/json.h>

using json = nlohmann::json;
auto match_cont = std::regex_constants::match_continuous;

using namespace cyberprobe::tcpip;
using namespace cyberprobe::probe;

std::vector<std::string> commands;
std::vector<std::string> add_commands;
std::vector<std::string> remove_commands;
std::vector<std::string> show_commands;
std::vector<std::string> classes;

std::vector<std::string>::iterator table_pos;
std::vector<std::string>::iterator table_end;

void cmd_json(tcp_socket& sock, const json& req, json& res)
{

    sock.write(req.dump() + "\n");

    std::string line;
    sock.readline(line);
    int len = std::stoi(line);
    sock.read(line, len);
    res = json::parse(line);

    if (res["status"].is_null())
        throw std::runtime_error("No 'status' field");

    int status = res["status"].get<int>();
    if (status < 200 || status >= 300) {
        if (res["message"].is_null())
            throw std::runtime_error("Error status, but no 'message' field");
        throw std::runtime_error(res["message"]);
    }

}

bool cmd_auth(tcp_socket& sock,
              const std::string& username,
              const std::string& password)
{

    try {

        json req = {
            {"action", "auth"},
            {"username", username},
            {"password", password}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}
        
bool cmd_add_interface(tcp_socket& sock,
                       const std::string& ifa,
                       const std::string& delay,
                       const std::string& filter)
{

    try {

        interface::spec sp;
        sp.ifa = ifa;
        if (delay != "")
            sp.delay = std::stof(delay);
        else
            sp.delay = 0.0;
        sp.filter = filter;
        
        json req = {
            {"action", "add-interface"},
            {"interface", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}
 
bool cmd_remove_interface(tcp_socket& sock,
                       const std::string& ifa,
                       const std::string& delay,
                       const std::string& filter)
{

    try {

        interface::spec sp;
        sp.ifa = ifa;
        if (delay != "")
            sp.delay = std::stof(delay);
        else
            sp.delay = 0.0;
        sp.filter = filter;
        
        json req = {
            {"action", "remove-interface"},
            {"interface", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}
     
bool cmd_add_target(tcp_socket& sock,
                    const std::string& device,
                    const std::string& cls,
                    const std::string& addr,
                    const std::string& network)
{

    try {

        target::spec sp;

        sp.device = device;

        std::string address;

        int pos = addr.find("/");
        if (pos != -1) {
            sp.mask = std::stoi(addr.substr(pos + 1));
            address = addr.substr(0, pos);
        } else if (cls == "ipv6") {
            address = addr;
            sp.mask = 128;
        } else {
            address = addr;
            sp.mask = 32;
        }

        if (cls == "ipv6") {
            sp.universe = sp.IPv6;
            sp.addr6.from_string(address);
        } else {
            sp.universe = sp.IPv4;
            sp.addr.from_string(address);
        }

        sp.network = network;
        
        json req = {
            {"action", "add-target"},
            {"target", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}
bool cmd_remove_target(tcp_socket& sock,
                       const std::string& device,
                       const std::string& cls,
                       const std::string& addr,
                       const std::string& network)
{

    try {

        target::spec sp;

        sp.device = device;

        std::string address;

        int pos = addr.find("/");
        if (pos != -1) {
            sp.mask = std::stoi(addr.substr(pos + 1));
            address = addr.substr(0, pos);
        } else if (cls == "ipv6") {
            address = addr;
            sp.mask = 128;
        } else {
            address = addr;
            sp.mask = 32;
        }

        if (cls == "ipv6") {
            sp.universe = sp.IPv6;
            sp.addr6.from_string(address);
        } else {
            sp.universe = sp.IPv4;
            sp.addr.from_string(address);
        }

        sp.network = network;
        
        json req = {
            {"action", "remove-target"},
            {"target", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}

bool cmd_add_parameter(tcp_socket& sock,
                        const std::string& k,
                        const std::string& v)
{

    try {

        parameter::spec sp;
        sp.key = k;
        sp.val = v;
        
        json req = {
            {"action", "add-parameter"},
            {"parameter", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}
  
bool cmd_remove_parameter(tcp_socket& sock,
                          const std::string& k)
{

    try {

        parameter::spec sp;
        sp.key = k;
        
        json req = {
            {"action", "remove-parameter"},
            {"parameter", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}
  
bool cmd_add_endpoint(tcp_socket& sock,
                      const std::string& hostname,
                      const std::string& port,
                      const std::string& type,
                      const std::string& transport,
                      const std::string& key,
                      const std::string& cert,
                      const std::string& ca)
{

    try {

        endpoint::spec sp;
        sp.hostname = hostname;
        sp.port = std::stoi(port);
        sp.type = type;
        sp.transport = transport;
        sp.key_file = key;
        sp.certificate_file = cert;
        sp.trusted_ca_file = ca;

        if (sp.transport == "")
            sp.transport = "tcp";

        json req = {
            {"action", "add-endpoint"},
            {"endpoint", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}

bool cmd_remove_endpoint(tcp_socket& sock,
                      const std::string& hostname,
                      const std::string& port,
                      const std::string& type,
                      const std::string& transport,
                      const std::string& key,
                      const std::string& cert,
                      const std::string& ca)
{

    try {

        endpoint::spec sp;
        sp.hostname = hostname;
        sp.port = std::stoi(port);
        sp.type = type;
        sp.transport = transport;
        sp.key_file = key;
        sp.certificate_file = cert;
        sp.trusted_ca_file = ca;

        if (sp.transport == "")
            sp.transport = "tcp";

        json req = {
            {"action", "remove-endpoint"},
            {"endpoint", sp}
        };

        json res;
        cmd_json(sock, req, res);
        return true;

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }

}

void cmd_help()
{
    std::cerr << "Not implemented. :) " << std::endl;
}

void cmd_endpoints(tcp_socket& sock) 
{

    json req = {
        { "action", "get-endpoints" }
    };

    json res;

    try {

        cmd_json(sock, req, res);

        std::list<endpoint::spec> es;
        res["endpoints"].get_to(es);

        std::cout.setf(std::ios::left);

        std::cout << std::setw(40) << "Hostname"
                  << std::setw(8) << "Port"
                  << std::setw(10) << "Type"
                  << std::endl;
    
        std::cout << std::setw(40) << "--------"
                  << std::setw(8) << "----"
                  << std::setw(10) << "----"
                  << std::endl;
        
        for(auto it = es.begin(); it != es.end(); it++) {

            std::cout << std::setw(40) << it->hostname
                      << std::setw(8) << it->port
                      << std::setw(10) << it->type
                      << std::endl;

        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return;
    }
    
}

void cmd_targets(tcp_socket& sock) 
{

    json req = {
        { "action", "get-targets" }
    };

    json res;

    try {

        cmd_json(sock, req, res);

        std::list<target::spec> ts;
        res["targets"].get_to(ts);

        std::cout.setf(std::ios::left);

        std::cout << std::setw(20) << "Device"
                  << std::setw(8) << "Class"
                  << std::setw(30) << "Address"
                  << std::setw(8) << "Mask"
                  << std::endl;
        
        std::cout << std::setw(20) << "----"
                  << std::setw(8) << "-----"
                  << std::setw(30) << "-------"
                  << std::setw(8) << "----"
                  << std::endl;
    
        for(auto it = ts.begin(); it != ts.end(); it++) {

            std::string cls =
                (it->universe == it->IPv6) ?
                "ipv6" : "ipv4";

            std::string addr;
            if (it->universe == it->IPv6)
                it->addr6.to_string(addr);
            else
                it->addr.to_string(addr);
            
            std::cout << std::setw(20) << it->device
                      << std::setw(8) << cls
                      << std::setw(30) << addr
                      << "/"
                      << std::setw(8) << it->mask
                      << std::endl;
            
        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return;
    }
      
}

void cmd_interfaces(tcp_socket& sock) 
{

    json req = {
        { "action", "get-interfaces" }
    };

    json res;

    try {

        cmd_json(sock, req, res);

        std::list<interface::spec> ifs;
        res["interfaces"].get_to(ifs);

        std::cout.setf(std::ios::left);

        std::cout << std::setw(20) << "Interface"
                  << std::setw(8) << "Delay"
                  << std::setw(50) << "Filter"
                  << std::endl;
    
        std::cout << std::setw(20) << "---------"
                  << std::setw(8) << "-----"
                  << std::setw(50) << "------"
                  << std::endl;
    
        for(auto it = ifs.begin(); it != ifs.end(); it++) {

            std::cout << std::setw(20) << it->ifa
                      << std::setw(8) << it->delay
                      << std::setw(50) << it->filter
                      << std::endl;

        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return;
    }
      
}

void cmd_parameters(tcp_socket& sock) 
{

    json req = {
        { "action", "get-parameters" }
    };

    json res;

    try {

        cmd_json(sock, req, res);

        std::list<parameter::spec> ps;
        res["parameters"].get_to(ps);

        std::cout.setf(std::ios::left);

        std::cout << std::setw(30) << "Key"
                  << std::setw(45) << "Value"
                  << std::endl;
        
        std::cout << std::setw(30) << "---"
                  << std::setw(45) << "-----"
                  << std::endl;
        
        for(auto it = ps.begin(); it != ps.end(); it++) {

            std::cout << std::setw(30) << it->key
                      << std::setw(45) << it->val
                      << std::endl;

        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return;
    }
  
}

bool generator(const std::string& partial, std::string& match) 
{
    
    while (table_pos != table_end) {

	if (table_pos->substr(0, partial.size()) == partial) {
	    match = *table_pos;
	    table_pos++;
	    return true;
	}
	
	table_pos++;
	
    }

    readline::completion_over();

    return false;

}

void completer(const std::vector<std::string>& tokens,
	       const std::string& token,
	       int cur_token,
	       std::vector<std::string>& completions)
{

    if (cur_token == 0) {
	table_pos = commands.begin();
	table_end = commands.end();
	readline::make_completions(completions, token, generator);
	return;
    }

    if ((cur_token == 1) && (tokens[0] == "add")) {
    	table_pos = add_commands.begin();
    	table_end = add_commands.end();
	readline::make_completions(completions, token, generator);
    }

    if ((cur_token == 1) && (tokens[0] == "remove")) {
    	table_pos = remove_commands.begin();
    	table_end = remove_commands.end();
	readline::make_completions(completions, token, generator);
    }

    if ((cur_token == 1) && (tokens[0] == "show")) {
    	table_pos = show_commands.begin();
    	table_end = show_commands.end();
	readline::make_completions(completions, token, generator);
    }

    if ((cur_token > 1) && 
	(tokens[0] == "add") && (tokens[1] == "interface")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add interface <interface> <delay> <filter>" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token > 1) && 
	(tokens[0] == "remove") && (tokens[1] == "interface")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove interface <interface> <delay> <filter>" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token > 1) && 
	(tokens[0] == "add") && (tokens[1] == "endpoint")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add endpoint <host> <port> <type> [<transport> [<key> <cert> <ca>]]" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token > 1) && 
	(tokens[0] == "remove") && (tokens[1] == "endpoint")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove endpoint <host> <port> <type>" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token == 3) &&
	(tokens[0] == "add") && (tokens[1] == "target")) {
    	table_pos = classes.begin();
    	table_end = classes.end();
	readline::make_completions(completions, token, generator);
	return;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "add") && (tokens[1] == "target")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add target <device> [ipv4|ipv6] <address> [<network>]" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token == 2) &&
	(tokens[0] == "remove") && (tokens[1] == "target")) {
    	table_pos = classes.begin();
    	table_end = classes.end();
	readline::make_completions(completions, token, generator);
	return;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "remove") && (tokens[1] == "target")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove target [ipv4|ipv6] <address>" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "add") && (tokens[1] == "parameter")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add parameter <key> <value>" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "remove") && (tokens[1] == "parameter")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove parameter <key> <value>" 
		  << std::endl;
	readline::completion_over();
	readline::force_display_update();
	return;
    }

    readline::completion_over();

}

int client(int argc, char** argv)
{

    if (argc != 3) {
	std::cerr << "Usage:" << std::endl
		  << "\tcyberprobe_cli host port" << std::endl;
	exit(1);
    }

    commands.push_back("add");
    commands.push_back("remove");
    commands.push_back("show");
    commands.push_back("quit");
    commands.push_back("help");

    add_commands.push_back("interface");
    add_commands.push_back("target");
    add_commands.push_back("endpoint");
    add_commands.push_back("parameter");

    remove_commands = add_commands;

    show_commands.push_back("interfaces");
    show_commands.push_back("targets");
    show_commands.push_back("endpoints");
    show_commands.push_back("parameters");

    classes.push_back("ipv4");
    classes.push_back("ipv6");

    setupterm(getenv("TERM"), 1, 0);

    std::string host = argv[1];
    
    std::istringstream buf(argv[2]);
    unsigned int port;
    buf >> port;

    tcp_socket sock;
    sock.connect(host, port);

    std::cout << "Connected.  You must authenticate." << std::endl;

    while (1) {

	std::string user, password;

	readline::get_line("User: ", user);

	readline::get_password("Password: ", password);

        try {
            bool success = cmd_auth(sock, user, password);
            if (success) break;
        } catch (std::exception& e) {
            std::cerr << e.what() << std::endl;
        }

    }

    while (1) {

	std::string s;
	readline::get_line_completing("> ", s, completer);

	static const std::regex 
	    help(" *help *$", std::regex::extended);

	std::match_results<std::string::const_iterator> what;

	if (regex_search(s, help, match_cont)) {
	    cmd_help();
	    continue;
	}

	static const std::regex 
	    endpoints(" *show +endpoints *$", std::regex::extended);

	if (regex_search(s, endpoints, match_cont)) {
	    cmd_endpoints(sock);
	    continue;
	}

	static const std::regex 
	    targets(" *show +targets *$", std::regex::extended);

	if (regex_search(s, targets, match_cont)) {
	    cmd_targets(sock);
	    continue;
	}

	static const std::regex 
	    interfaces(" *show +interfaces *$", std::regex::extended);

	if (regex_search(s, interfaces, match_cont)) {
	    cmd_interfaces(sock);
	    continue;
	}

	static const std::regex 
	    parameters(" *show +parameters *$", std::regex::extended);

	if (regex_search(s, parameters, match_cont)) {
	    cmd_parameters(sock);
	    continue;
	}

	static const std::regex 
	    add_interface(" *add +interface +([^ ]+) *([^ ]+)? *(.*)?$", 
			  std::regex::extended);

	if (regex_search(s, what, add_interface, match_cont)) {
	    cmd_add_interface(sock, what[1], what[2], what[3]);
	    continue;
	}

	static const std::regex 
	    remove_interface(" *remove +interface +([^ ]+) *([^ ]+)? *(.*)?$", 
                             std::regex::extended);

	if (regex_search(s, what, remove_interface,
                         match_cont)) {
	    cmd_remove_interface(sock, what[1], what[2], what[3]);
	    continue;
	}

	static const std::regex 
	    add_target(" *add +target +([^ ]+) +([^ ]+) +([^ ]+) *([^ ]+)? *$", 
                       std::regex::extended);

	if (regex_search(s, what, add_target, match_cont)) {
	    cmd_add_target(sock, what[1], what[2], what[3], what[4]);
	    continue;
	}

	static const std::regex 
	    remove_target(" *remove +target +([^ ]+) +([^ ]+) +([^ ]+) *([^ ]+)? *$", 
			  std::regex::extended);
	
	if (regex_search(s, what, remove_target, match_cont)) {
	    cmd_remove_target(sock, what[1], what[2], what[3], what[4]);
	    continue;
	}

	static const std::regex 
	    add_parameter(" *add +parameter +([^ ]+) +(.*) *$", 
			  std::regex::extended);

	if (regex_search(s, what, add_parameter, match_cont)) {
	    cmd_add_parameter(sock, what[1], what[2]);
	    continue;
	}

	static const std::regex 
	    remove_parameter(" *remove +parameter +([^ ]+) *$", 
                             std::regex::extended);
	
	if (regex_search(s, what, remove_parameter, match_cont)) {
	    cmd_remove_parameter(sock, what[1]);
	    continue;
	}

	static const std::regex 
	    add_endpoint(" *add +endpoint +([^ ]+) +([^ ]+) +([^ ]+) *([^ ]+)? *([^ ]+)? *([^ ]+)? *([^ ]+)? *$", 
                         std::regex::extended);

	if (regex_search(s, what, add_endpoint, match_cont)) {
	    cmd_add_endpoint(sock, what[1], what[2], what[3], what[4],
                             what[5], what[6], what[7]);
	    continue;
	}

	static const std::regex 
	    remove_endpoint(" *remove +endpoint +([^ ]+) +([^ ]+) +([^ ]+) *([^ ]+)? *([^ ]+)? *([^ ]+)? *([^ ]+)? *$", 
                            std::regex::extended);
	
	if (regex_search(s, what, remove_endpoint, match_cont)) {
	    cmd_remove_endpoint(sock, what[1], what[2], what[3], what[4],
                                what[5], what[6], what[7]);
	    continue;
	}

	std::cerr << "Command not understood." << std::endl;
	continue;

    }

}

int main(int argc, char** argv)
{
    try {
	client(argc, argv);
    } catch (std::exception& e) {
	std::cerr << "Exception: " << e.what() << std::endl;
    }
    exit(0);
}


#include "readline.h"
#include <iostream>
#include <sstream>
#include <cybermon/socket.h>
#include <vector>
#include <regex>
#include <iomanip>

std::vector<std::string> commands;
std::vector<std::string> add_commands;
std::vector<std::string> remove_commands;
std::vector<std::string> show_commands;
std::vector<std::string> classes;

std::vector<std::string>::iterator table_pos;
std::vector<std::string>::iterator table_end;

std::string get_status(const std::string& line)
{
    int pos = line.find(" ");
    if (pos != -1)
	return line.substr(0, pos);
    else
	return "";
}

bool cmd_data(tcpip::tcp_socket& sock, const std::string& cmd, 
	      std::string& result) 
{

    sock.write(cmd + "\n");

    std::string line;
    sock.readline(line);
    if (get_status(line) != "201") {
	std::cout << line << std::endl;
	return false;
    }
    
    sock.readline(line);
    std::istringstream buf(line);
    int len;
    buf >> std::dec >> len;

    sock.read(result, len);

    return true;

}
    
void cmd_do(tcpip::tcp_socket& s, const std::string& cmd)
{

    s.write(cmd + "\n");

    std::string line;
    s.readline(line);

    if (get_status(line) != "200")
	std::cerr << line << std::endl;

}

void cmd_do2(tcpip::tcp_socket& s, const std::string& c1, 
	     const std::string& c2)
{
    std::string cmd = c1 + " " + c2;
    cmd_do(s, cmd);
}

void cmd_do3(tcpip::tcp_socket& s, const std::string& c1, 
	     const std::string& c2, const std::string& c3)
{
    std::string cmd = c1 + " " + c2 + " " + c3;
    cmd_do(s, cmd);
}

void cmd_do4(tcpip::tcp_socket& s, const std::string& c1, 
	     const std::string& c2, const std::string& c3, 
	     const std::string& c4)
{
    std::string cmd = c1 + " " + c2 + " " + c3 + " " + c4;
    cmd_do(s, cmd);
}

void cmd_do5(tcpip::tcp_socket& s, const std::string& c1, 
	     const std::string& c2, const std::string& c3, 
	     const std::string& c4, const std::string& c5)
{
    std::string cmd = c1 + " " + c2 + " " + c3 + " " + c4 + " " + c5;
    cmd_do(s, cmd);
}

void cmd_help()
{
    std::cerr << "Not implemented. :) " << std::endl;
}

void cmd_endpoints(tcpip::tcp_socket& sock) 
{

    std::string result;

    cmd_data(sock, "endpoints", result);

    std::cout.setf(std::ios::left);

    std::cout << std::setw(40) << "Hostname"
	      << std::setw(8) << "Port"
	      << std::setw(10) << "Type"
	      << std::endl;
    
    std::cout << std::setw(40) << "--------"
	      << std::setw(8) << "----"
	      << std::setw(10) << "----"
	      << std::endl;
    
    while (1) {

	int pos = result.find(":");
	if (pos == -1) break;
	std::string hostname = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find(":");
	if (pos == -1) break;
	std::string port = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find(":");
	if (pos == -1) break;
	std::string type = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find("\n");
	if (pos == -1) break;
	std::string desc = result.substr(0, pos);
	result = result.substr(pos + 1);

	std::cout << std::setw(40) << hostname
		  << std::setw(8) << port
		  << std::setw(10) << type
		  << std::endl;

    }
    
}

void cmd_targets(tcpip::tcp_socket& sock) 
{

    std::string result;
    cmd_data(sock, "targets", result);

    std::cout.setf(std::ios::left);

    std::cout << std::setw(20) << "LIID"
	      << std::setw(8) << "Class"
	      << std::setw(30) << "Address"
	      << std::endl;
    
    std::cout << std::setw(20) << "----"
	      << std::setw(8) << "-----"
	      << std::setw(30) << "-------"
	      << std::endl;
    
    while (1) {

	int pos = result.find(":");
	if (pos == -1) break;
	std::string liid = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find(":");
	if (pos == -1) break;
	std::string cls = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find("\n");
	if (pos == -1) break;
	std::string addr = result.substr(0, pos);
	result = result.substr(pos + 1);

	std::cout << std::setw(20) << liid
		  << std::setw(8) << cls
		  << std::setw(30) << addr
		  << std::endl;

    }
    
}

void cmd_interfaces(tcpip::tcp_socket& sock) 
{

    std::string result;
    cmd_data(sock, "interfaces", result);

    std::cout.setf(std::ios::left);

    std::cout << std::setw(20) << "Interface"
	      << std::setw(8) << "Delay"
	      << std::setw(50) << "Filter"
	      << std::endl;
    
    std::cout << std::setw(20) << "---------"
	      << std::setw(8) << "-----"
	      << std::setw(50) << "------"
	      << std::endl;
    
    while (1) {

	int pos = result.find(":");
	if (pos == -1) break;
	std::string interface = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find(":");
	if (pos == -1) break;
	std::string delay = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find("\n");
	if (pos == -1) break;
	std::string filter = result.substr(0, pos);
	result = result.substr(pos + 1);

	std::cout << std::setw(20) << interface
		  << std::setw(8) << delay
		  << std::setw(50) << filter
		  << std::endl;

    }
    
}

void cmd_parameters(tcpip::tcp_socket& sock) 
{

    std::string result;
    cmd_data(sock, "parameters", result);

    std::cout.setf(std::ios::left);

    std::cout << std::setw(30) << "Key"
	      << std::setw(45) << "Value"
	      << std::endl;
    
    std::cout << std::setw(30) << "---"
	      << std::setw(45) << "-----"
	      << std::endl;
    
    while (1) {

	int pos = result.find(":");
	if (pos == -1) break;
	std::string key = result.substr(0, pos);
	result = result.substr(pos + 1);

	pos = result.find("\n");
	if (pos == -1) break;
	std::string value = result.substr(0, pos);
	result = result.substr(pos + 1);

	std::cout << std::setw(30) << key
		  << std::setw(45) << value
		  << std::endl;

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
	std::cerr << "    add endpoint <host> <port> <type>" 
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
	std::cerr << "    add target <liid> [ipv4|ipv6] <address>" 
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

    tcpip::tcp_socket sock;
    sock.connect(host, port);

    std::cout << "Connected.  You must authenticate." << std::endl;

    while (1) {

	std::string user, password;

	readline::get_line("User: ", user);

	readline::get_password("Password: ", password);

	std::string cmd = "auth " + user + " " + password + "\n";

	sock.write(cmd);

	std::string response;
	sock.readline(response);

	std::string status;
	int pos = response.find(" ");
	if (pos != -1)
	    status = response.substr(0, pos);

	if (status == "200") {
	    std::cout << "Authentication successful." << std::endl;
	    break;
	} else
	    std::cout << response << std::endl;

    }

    while (1) {

	std::string s;
	readline::get_line_completing("> ", s, completer);

	static const std::regex 
	    help(" *help *$", std::regex::extended);

	std::match_results<std::string::const_iterator> what;

	if (regex_search(s, help, std::regex_constants::match_continuous)) {
	    cmd_help();
	    continue;
	}

	static const std::regex 
	    endpoints(" *show +endpoints *$", std::regex::extended);

	if (regex_search(s, endpoints, std::regex_constants::match_continuous)) {
	    cmd_endpoints(sock);
	    continue;
	}

	static const std::regex 
	    targets(" *show +targets *$", std::regex::extended);

	if (regex_search(s, targets, std::regex_constants::match_continuous)) {
	    cmd_targets(sock);
	    continue;
	}

	static const std::regex 
	    interfaces(" *show +interfaces *$", std::regex::extended);

	if (regex_search(s, interfaces, std::regex_constants::match_continuous)) {
	    cmd_interfaces(sock);
	    continue;
	}

	static const std::regex 
	    parameters(" *show +parameters *$", std::regex::extended);

	if (regex_search(s, parameters, std::regex_constants::match_continuous)) {
	    cmd_parameters(sock);
	    continue;
	}

	static const std::regex 
	    add_interface(" *add +interface +([^ ]+) +([^ ]+) *$", 
			  std::regex::extended);

	if (regex_search(s, what, add_interface, std::regex_constants::match_continuous)) {
	    cmd_do3(sock, "add_interface", what[1], what[2]);
	    continue;
	}

	static const std::regex 
	    remove_interface(" *remove +interface +([^ ]+) +([^ ]+) *$", 
                             std::regex::extended);

	if (regex_search(s, what, remove_interface, std::regex_constants::match_continuous)) {
	    cmd_do3(sock, "remove_interface", what[1], what[2]);
	    continue;
	}

	static const std::regex 
	    add_target(" *add +target +([^ ]+) +([^ ]+) +([^ ]+) *$", 
                       std::regex::extended);

	if (regex_search(s, what, add_target, std::regex_constants::match_continuous)) {
	    cmd_do4(sock, "add_target", what[1], what[2], what[3]);
	    continue;
	}

	static const std::regex 
	    remove_target(" *remove +target +([^ ]+) +([^ ]+) *$", 
			  std::regex::extended);
	
	if (regex_search(s, what, remove_target, std::regex_constants::match_continuous)) {
	    cmd_do3(sock, "remove_target", what[1], what[2]);
	    continue;
	}

	static const std::regex 
	    add_parameter(" *add +parameter +([^ ]+) +(.*) *$", 
			  std::regex::extended);

	if (regex_search(s, what, add_parameter, std::regex_constants::match_continuous)) {
	    cmd_do3(sock, "add_parameter", what[1], what[2]);
	    continue;
	}

	static const std::regex 
	    remove_parameter(" *remove +parameter +([^ ]+) *$", 
                             std::regex::extended);
	
	if (regex_search(s, what, remove_parameter, std::regex_constants::match_continuous)) {
	    cmd_do2(sock, "remove_parameter", what[1]);
	    continue;
	}

	static const std::regex 
	    add_endpoint(" *add +endpoint +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) *$", 
                         std::regex::extended);

	if (regex_search(s, what, add_endpoint, std::regex_constants::match_continuous)) {
	    cmd_do5(sock, "add_endpoint", what[1], what[2], what[3],
		    what[4]);
	    continue;
	}

	static const std::regex 
	    remove_endpoint(" *remove +endpoint +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) *$", 
                            std::regex::extended);
	
	if (regex_search(s, what, remove_endpoint, std::regex_constants::match_continuous)) {
	    cmd_do5(sock, "remove_endpoint", what[1], what[2], what[3],
		    what[4]);
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

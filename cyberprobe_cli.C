
#include "readline.h"

#include <iostream>
#include <sstream>
#include <termios.h>

#include "rlwrap.h"

#include <term.h>

#include "socket.h"

#include <vector>

std::vector<std::string> commands;
std::vector<std::string> add_commands;
std::vector<std::string> remove_commands;
std::vector<std::string> show_commands;
std::vector<std::string> classes;

std::vector<std::string>::iterator table_pos;
std::vector<std::string>::iterator table_end;

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

int main(int argc, char** argv)
{

    if (argc != 3) {
	std::cerr << "Usage:" << std::endl
		  << "\tcyberprobe_cli host port" << std::endl;
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
	std::cout << s << std::endl;
    }

}


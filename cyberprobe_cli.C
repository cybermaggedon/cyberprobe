
#include "readline.h"

#include <iostream>
#include <sstream>
#include <termios.h>

#include "rlwrap.h"

#include <term.h>

#include "socket.h"

#include <vector>

void
blanked_password_redisplay()
{

    std::string prompt = rl_prompt;
    std::string line_buf = rl_line_buffer;

    putp(tigetstr((char*)"cr"));

    std::cout << "\r" << prompt;

    for(unsigned int i = 0; i < line_buf.size(); i++)
	std::cout << "*";

    putp(tigetstr((char*)"el"));

    for(int i = 0; i < (rl_end - rl_point); i++)
	putp(tigetstr((char*)"cub1"));

    std::cout.flush();

}

std::vector<std::string> commands;
std::vector<std::string> add_commands;
std::vector<std::string> remove_commands;
std::vector<std::string> show_commands;
std::vector<std::string> classes;

std::vector<std::string>::iterator table_pos;
std::vector<std::string>::iterator table_end;

char* command_generator(const char* text, int state)
{
    
//    static int pos;
    int len = strlen(text);

//    if (!state)
//	pos = 0;

    while (table_pos != table_end) {

	if (table_pos->substr(0, len) == text) {
	    char* result = strdup(table_pos->c_str());
	    table_pos++;
	    return result;
	}
	
	table_pos++;
	
    }
    
    rl_attempted_completion_over = 1;

    return 0;

}

char** complete(const char* text, int start, int end)
{

    static bool init = false;
    if (!init) {
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
	init = true;
    }

    std::vector<std::string> tokens;
    int cur_token = -1;

    unsigned int pos = 0;

    std::string buf = rl_line_buffer;

    std::string token;

    while (pos < buf.size()) {
	if ((int) pos == start)
	    cur_token = tokens.size();

	bool whitespace = (buf[pos] == ' ') || (buf[pos] == '\t');

	if (whitespace) {
	    if (token != "") {
		tokens.push_back(token);
		token = "";
	    }
	    pos++;
	    continue;
	}

	token += buf[pos++];
	
    }

    if ((int) pos == start)
	cur_token = tokens.size();

    if (token != "") tokens.push_back(token);

    // ------------------------------

    if (cur_token == 0) {
	table_pos = commands.begin();
	table_end = commands.end();
	return rl_completion_matches (text, command_generator);
    }

    if ((cur_token == 1) && (tokens[0] == "add")) {
    	table_pos = add_commands.begin();
    	table_end = add_commands.end();
	return rl_completion_matches (text, command_generator);
    }

    if ((cur_token > 1) && 
	(tokens[0] == "add") && (tokens[1] == "interface")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add interface <interface> <delay> <filter>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token > 1) && 
	(tokens[0] == "remove") && (tokens[1] == "interface")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove interface <interface> <delay> <filter>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "add") && (tokens[1] == "endpoint")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add endpoint <host> <port> <type>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "remove") && (tokens[1] == "endpoint")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove endpoint <host> <port> <type>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token == 3) &&
	(tokens[0] == "add") && (tokens[1] == "target")) {
    	table_pos = classes.begin();
    	table_end = classes.end();
	return rl_completion_matches (text, command_generator);
	return 0;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "add") && (tokens[1] == "target")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add target <liid> [ipv4|ipv6] <address>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token == 2) &&
	(tokens[0] == "remove") && (tokens[1] == "target")) {
    	table_pos = classes.begin();
    	table_end = classes.end();
	return rl_completion_matches (text, command_generator);
	return 0;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "remove") && (tokens[1] == "target")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove target [ipv4|ipv6] <address>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "add") && (tokens[1] == "parameter")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    add parameter <key> <value>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token > 1) &&
	(tokens[0] == "remove") && (tokens[1] == "parameter")) {
	std::cerr << std::endl << "  Usage:" << std::endl;
	std::cerr << "    remove parameter <key> <value>" 
		  << std::endl;
	rl_attempted_completion_over = 1;
	rl_forced_update_display();
	return 0;
    }

    if ((cur_token == 1) && (tokens[0] == "remove")) {
    	table_pos = remove_commands.begin();
    	table_end = remove_commands.end();
	return rl_completion_matches (text, command_generator);
    }

    if ((cur_token == 1) && (tokens[0] == "show")) {
    	table_pos = show_commands.begin();
    	table_end = show_commands.end();
	return rl_completion_matches (text, command_generator);
    }

    rl_attempted_completion_over = 1;

    return 0;


    std::cerr << std::endl << "Text: " << text << std::endl;
    std::cerr << "Start: " << start << "  End: " << end << std::endl;

    for(std::vector<std::string>::iterator it = tokens.begin();
	it != tokens.end();
	it++) {
	std::cerr << "TOKEN: " << *it << std::endl;
    }
    std::cerr << "CUR_TOKEN: " << cur_token << std::endl;

    rl_forced_update_display();

    return 0;

    if (start == 0)
	return rl_completion_matches (text, command_generator);

    return 0;

}

int main(int argc, char** argv)
{

    if (argc != 3) {
	std::cerr << "Usage:" << std::endl
		  << "\tcyberprobe_cli host port" << std::endl;
    }

    setupterm(getenv("TERM"), 1, 0);

    std::string host = argv[1];
    
    std::istringstream buf(argv[2]);
    unsigned int port;
    buf >> port;

    rl_attempted_completion_function = &complete;

    while (1) {
	std::string s;
	readline::get_line("> ", s);
	std::cout << s << std::endl;
    }

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

}


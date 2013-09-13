
#include "control.h"
#include "management.h"

#include <vector>

using namespace control;

// Called by a connection when it terminates to request tidy-up.
void service::close_me(connection* c)
{

    // Just puts the connection on a list to clear up.
    close_me_lock.lock();
    close_mes.push(c);
    close_me_lock.unlock();

}

// service body, handles connections.
void service::run()
{

    try {
	svr.bind(sp.port);
	svr.listen();
    } catch (std::exception& e) {
	std::cerr << "Failed to start control service: " 
		  << e.what() << std::endl;
	return;
    }

    while (running) {

	// Wait for connection.
	bool activ = svr.poll(1.0);

	if (activ) {

	    // Accept the connection
	    tcpip::tcp_socket cn;
	    svr.accept(cn);

	    // Spawn a connection thread.
	    connection* c = new connection(cn, d, *this, sp);
	    connections.push_back(c);
	    c->start();

	}

	// Tidy up any connections which need clearing up.
	close_me_lock.lock();
	while (!close_mes.empty()) {

	    // Wait for thread to close.
	    close_mes.front()->join();

	    // Delete resource.
	    delete close_mes.front();
	    connections.remove(close_mes.front());

	    close_mes.pop();
	}
	close_me_lock.unlock();

    }

    // Signal all connections to close
    for(std::list<connection*>::iterator it = connections.begin();
	it != connections.end();
	it++)
	(*it)->stop();

    // Now wait for threads, and delete.
    for(std::list<connection*>::iterator it = connections.begin();
	it != connections.end();
	it++) {
	(*it)->join();
	delete *it;
    }

    svr.close();

}

// Command line tokenisation.  Looks for space-separated tokens, just
// returns a list of tokens.
void connection::tokenise(const std::string& line, 
			  std::vector<std::string>& tok)
{

    std::string left = line;

    tok.clear();

    while (left != "") {
	
	int pos = left.find(" ");
	if (pos != -1) {

	    tok.push_back(left.substr(0, pos));

	    left = left.substr(pos + 1);

	    while (left != "" && left[0] == ' ')
		left == left.substr(1);

	} else {

	    tok.push_back(left);
	    left = "";

	}

    }

}

// Return an OK response (should be status=200).
void connection::ok(int status, const std::string& msg)
{
    std::ostringstream buf;
    buf << status << " " << msg << "\n";
    s.write(buf.str());
    std::cerr << "Reply: " << status << " " << msg << std::endl;
}

// Return an ERROR response (should be status=3xx or 5xx).
void connection::error(int status, const std::string& msg)
{
    std::ostringstream buf;
    buf << status << " " << msg << "\n";
    s.write(buf.str());
    std::cerr << "Reply: " << status << " " << msg << std::endl;
}

// Return an OK response with payload (should be status=201).
void connection::response(int status, const std::string& msg,
			  const std::string& resp)
{
    std::ostringstream buf;
    buf << status << " " << msg << "\n" 
	<< resp.size() << "\n";
    s.write(buf.str());
    s.write(resp);
    std::cerr << "Reply: " << status << " " << msg << std::endl;
}

// 'endpoints' command.
void connection::cmd_endpoints()
{

    std::list<sender_info> si;
    d.get_endpoints(si);
    
    std::ostringstream buf;
    
    for(std::list<sender_info>::iterator it = si.begin();
	it != si.end();
	it++) {
	buf << it->hostname << ":" << it->port << ":" 
	    << it->type << ":" << it->description << "\n";
    }

    response(201, "Endpoints list follows.", buf.str());

}

// 'interfaces' command.
void connection::cmd_interfaces()
{

    std::list<interface_info> ii;
    
    try {
	d.get_interfaces(ii);
    } catch (std::exception& e) {
	error(500, e.what());
	return;
    }

    std::ostringstream buf;
    
    for(std::list<interface_info>::iterator it = ii.begin();
	it != ii.end();
	it++) {
	buf << it->interface << ":" << it->delay << ":" 
	    << it->filter << "\n";
    }
    
    response(201, "Interfaces list follows.", buf.str());

}

// 'parameters' command.
void connection::cmd_parameters()
{

    std::map<std::string,std::string> p;
    
    d.get_parameters(p);

    std::ostringstream buf;
    
    for(std::map<std::string,std::string>::iterator it = p.begin();
	it != p.end();
	it++) {
	buf << it->first << ":" << it->second << "\n";
    }
    
    response(201, "Paramter list follows.", buf.str());

}

// 'targets' command.
void connection::cmd_targets()
{

    std::map<tcpip::ip4_address, std::string> t4;
    std::map<tcpip::ip6_address, std::string> t6;
		    
    d.get_targets(t4, t6);

    std::ostringstream buf;
    
    for(std::map<tcpip::ip4_address, std::string>::iterator it
	    = t4.begin();
	it != t4.end();
	it++) {
	buf << it->second << ":" << "ipv4" << ":" 
	    << it->first << "\n";
    }
    
    for(std::map<tcpip::ip6_address, std::string>::iterator it
	    = t6.begin();
	it != t6.end();
	it++) {
	buf << it->second << ":" << "ipv6" << ":" 
	    << it->first << "\n";
    }
    
    response(201, "Targets list follows.", buf.str());

}

// 'add_interface' command.
void connection::cmd_add_interface(const std::vector<std::string>& lst)
{

    if (lst.size() != 3 && lst.size() != 4) {
	error(301, "Usage: add_interface <if> <del> [<fltr>]");
	return;
    }
    
    std::string iface = lst[1];
    float delay;
    std::istringstream buf(lst[2]);
    buf >> delay;
    std::string filter;
    
    if (lst.size() == 4)
	filter = lst[3];
    
    try {
	d.add_interface(iface, filter, delay);
	ok(200, "Added interface.");
    } catch (...) {
	error(500, "Failed to add interface.");
    }

}

// 'remove_interface' command.
void connection::cmd_remove_interface(const std::vector<std::string>& lst)
{

    if (lst.size() != 3 && lst.size() != 4) {
	error(301, "Usage: remove_interface <if> <del> [<fltr>]");
	return;
    }
    
    std::string iface = lst[1];
    float delay;
    std::istringstream buf(lst[2]);
    buf >> delay;
    std::string filter;
    
    if (lst.size() == 4)
	filter = lst[3];
    
    try {
	d.remove_interface(iface, filter, delay);
	ok(200, "Removed interface.");
    } catch (...) {
	error(500, "Failed to remove interface.");
    }
    
    
}

// 'add_target' command.
void connection::cmd_add_target(const std::vector<std::string>& lst)
{

    if (lst.size() != 4) {
	error(301, "Usage: add_target <liid> <class> <address>");
	return;
    }

    std::string liid = lst[1];
    std::string cls = lst[2];

    if (cls == "ipv4") {
	
	try {
	    tcpip::ip4_address a4(lst[3]);
	    d.add_target(a4, liid);
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}
	
	ok(200, "Added target.");
	return;
	
    }
    
    if (cls == "ipv6") {
	
	try {
	    tcpip::ip6_address a6(lst[3]);
	    d.add_target(a6, liid);
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}
	
	ok(200, "Added target.");
	return;
	
    }
    
    error(301, "Address class not recognised.");
    
}

// 'remove_target' command.
void connection::cmd_remove_target(const std::vector<std::string>& lst)
{

    if (lst.size() != 3) {
	error(301, "Usage: remove_target <class> <address>");
	return;
    }

    std::string cls = lst[1];
		    
    if (cls == "ipv4") {
	
	try {
	    tcpip::ip4_address a4(lst[2]);
	    d.remove_target(a4);
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}

	ok(200, "Removed target.");
	return;

    }

    if (cls == "ipv6") {
	
	try {
	    tcpip::ip6_address a6(lst[2]);
	    d.remove_target(a6);
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}
	
	ok(200, "Remove target.");
	return;
	
    }
    
    error(301, "Address class not recognised.");
    
}

// 'add_endpoint' command.
void connection::cmd_add_endpoint(const std::vector<std::string>& lst)
{

    if (lst.size() != 4) {
	error(301, "Usage: add_endpoint <host> <port> <type>");
	return;
    }
    
    std::string host = lst[1];
    int port;
    std::istringstream buf(lst[2]);
    buf >> port;
    std::string type = lst[3];
    
    try {
	d.add_endpoint(host, port, type);
	ok(200, "Added endpoint.");
    } catch (...) {
	error(500, "Failed to add endpoint.");
    }

}

// 'remove_endpoint' command.
void connection::cmd_remove_endpoint(const std::vector<std::string>& lst)
{

    if (lst.size() != 4) {
	error(301, "Usage: remove_endpoint <host> <port> <type>");
	return;
    }
    
    std::string host = lst[1];
    int port;
    std::istringstream buf(lst[2]);
    buf >> port;
    std::string type = lst[3];
    
    try {
	d.remove_endpoint(host, port, type);
	ok(200, "Removed endpoint.");
    } catch (...) {
	error(500, "Failed to remove endpoint.");
    }
    
    
}

// 'add_endpoint' command.
void connection::cmd_add_parameter(const std::vector<std::string>& lst)
{

    if (lst.size() != 3) {
	error(301, "Usage: add_parameter <key> <value>");
	return;
    }
    
    std::string key = lst[1];
    std::string val = lst[2];
    
    try {
	d.add_parameter(key, val);
	ok(200, "Added parameter.");
    } catch (...) {
	error(500, "Failed to add parameter.");
    }

}

// 'add_endpoint' command.
void connection::cmd_remove_parameter(const std::vector<std::string>& lst)
{

    if (lst.size() != 2) {
	error(301, "Usage: remove_parameter <key>");
	return;
    }
    
    std::string key = lst[1];
    
    try {
	d.remove_parameter(key);
	ok(200, "Removed parameter.");
    } catch (...) {
	error(500, "Failed to remove parameter.");
    }

}

// 'auth' command.
void connection::cmd_auth(const std::vector<std::string>& lst)
{
    if (lst.size() != 3) {
	error(301, "Usage: auth <user> <password>");
	return;
    }

    if (lst[1] == sp.username && lst[2] == sp.password) {
	auth = true;
	ok(200, "Authenticated.");
	return;
    }

    error(331, "Authentication failure.");

}

// 'help' command.
void connection::cmd_help()
{
    std::ostringstream buf;

    buf << "Commands:\n"
	<< "\n"
	<< "  auth <user> <password>\n"
	<< "\n"
	<< "  help\n"
	<< "\n"
	<< "  add_interface <iface> <delay> [<filter>]\n"
	<< "      Starts packet capture from an interface.\n"
	<< "\n"
	<< "  remove_interface <iface> <delay> [<filter>]\n"
	<< "      Removes a previously enabled packet capture.\n"
	<< "\n"
	<< "  interfaces\n"
	<< "      Lists all interfaces, output is format iface:delay:filter\n"
	<< "\n"
	<< "  add_endpoint <host> <port> <type>\n"
	<< "      Adds an endpoint to delivery data to.\n"
	<< "      where type is one of: etsi nhis1.1\n"
	<< "\n"
	<< "  remove_endpoint <host> <port> <type>\n"
	<< "      Removes a previously enabled endpoint.\n"
	<< "      where type is one of: etsi nhis1.1\n"
	<< "\n"
	<< "  endpoints\n"
	<< "      Lists endpoints, format is host:port:type:description\n"
	<< "\n"
	<< "  add_target <liid> <class> <address>\n"
	<< "      Adds a new targeted IP address.\n"
	<< "      where class is one of: ipv4 ipv6\n"
	<< "\n"
	<< "  remove_target <class> <address>\n"
	<< "      Removes a previously targeted IP address.\n"
	<< "      where class is one of: ipv4 ipv6\n"
	<< "\n"
	<< "  targets\n"
	<< "      Lists targets, format is liid:class:address\n"
	<< "\n"
	<< "  add_parameter <key> <val>\n"
	<< "      Adds a new parameter, or changes a parameter value.\n"
	<< "\n"
	<< "  remove_parameter <key>\n"
	<< "      Removes a parameter value.\n"
	<< "\n"
	<< "  parameters\n"
	<< "      Lists parameters, format is key:value\n"
	<< "\n";

    response(201, "Help information follows.", buf.str());
}

// ETSI LI connection body, handles a single connection.
void connection::run()
{

    try {

	while (running) {

	    std::string line;

	    try {

		// Keep checking the loop condition if we're idle.
		bool activ = s.poll(1.0);
		if (!activ) continue;

		// Get the next command.
		try {
		    s.readline(line);
		} catch (...) {
		    // Socket close, probably.
		    break;
		}

		std::cerr << "Command: " << line << std::endl;

		// Tokenise.
		std::vector<std::string> lst;
		tokenise(line, lst);

		if (lst.empty()) {
		    ok(200, "Nothing to do.");
		    continue;
		}

		if (lst.front() == "help") {
		    cmd_help();
		    continue;
		}

		if (lst.front() == "auth") {
		    cmd_auth(lst);
		    continue;
		}

		if (lst.front() == "quit") {
		    ok(200, "Tra, then.");
		    break;
		}

		// This is the authentication gate.  Can only do 'help' and
		// 'auth' until we've authenticated.
		if (!auth) {
		    error(330, "Authenticate before continuing.");
		    continue;
		}

		if (lst.front() == "endpoints") {
		    cmd_endpoints();
		    continue;
		} 
  
		if (lst.front() == "targets") {
		    cmd_targets();
		    continue;
		} 
  
		if (lst.front() == "interfaces") {
		    cmd_interfaces();
		    continue;
		}
  
		if (lst.front() == "parameters") {
		    cmd_parameters();
		    continue;
		}
  
		if (lst.front() == "add_interface") {
		    cmd_add_interface(lst);
		    continue;
		} 

		if (lst.front() == "remove_interface") {
		    cmd_remove_interface(lst);
		    continue;
		} 

		if (lst.front() == "add_target") {
		    cmd_add_target(lst);
		    continue;
		} 

		if (lst.front() == "remove_target") {
		    cmd_remove_target(lst);
		    continue;
		} 

		if (lst.front() == "add_endpoint") {
		    cmd_add_endpoint(lst);
		    continue;
		} 

		if (lst.front() == "remove_endpoint") {
		    cmd_remove_endpoint(lst);
		    continue;
		} 

		if (lst.front() == "add_parameter") {
		    cmd_add_parameter(lst);
		    continue;
		} 

		if (lst.front() == "remove_parameter") {
		    cmd_remove_parameter(lst);
		    continue;
		} 

		error(301, "Command not known.");

	    } catch (...) {
		break;
	    }

	}

    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

    // Close the connection.
    s.close();

    // Add me to the tidy-up-list.
    svc.close_me(this);

}



#include "control.h"
#include "management.h"

#include <vector>

using namespace control;

void service::close_me(connection* c)
{
    close_me_lock.lock();
    close_mes.push(c);
    close_me_lock.unlock();
}

// service body, handles connections.
void service::run()
{

    svr.bind(sp.port);
    svr.listen();

    while (running) {

	bool activ = svr.poll(1.0);

	if (activ) {

	    tcpip::tcp_socket cn;
	    svr.accept(cn);

	    connection* c = new connection(cn, d, *this);
	    c->start();

	}

	close_me_lock.lock();

	while (!close_mes.empty()) {
	    close_mes.front()->join();
	    delete close_mes.front();
	    close_mes.pop();
	}
	close_me_lock.unlock();

    }

}

void connection::tokenise(const std::string& line, 
			  std::vector<std::string>& tok)
{

    std::string left = line;

    tok.clear();

    while (left != "") {
	
	if (left.find(" ") != -1) {

	    tok.push_back(left.substr(0, left.find(" ")));

	    left = left.substr(left.find(" ") + 1);

	    while (left != "" && left[0] == ' ')
		left == left.substr(1);

	} else {

	    tok.push_back(left);
	    left = "";

	}

    }

}

void connection::ok(int status, const std::string& msg)
{
    std::ostringstream buf;
    buf << status << " " << msg << "\n";
    s.write(buf.str());
}

void connection::error(int status, const std::string& msg)
{
    std::ostringstream buf;
    buf << status << " " << msg << "\n";
    s.write(buf.str());
}

void connection::response(int status, const std::string& msg,
			  const std::string& resp)
{
    std::ostringstream buf;
    buf << status << " " << msg << "\n" 
	<< resp.size() << "\n";
    s.write(buf.str());
    s.write(resp);
}

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

void connection::cmd_interfaces()
{

    std::list<interface_info> ii;
    
    try {
    std::cerr << "GETTING" << std::endl;
	d.get_interfaces(ii);
    } catch (std::exception& e) {
    std::cerr << "BLASY" << std::endl;
	error(500, e.what());
	return;
    }
    std::cerr << "GOT INTERFACES" << std::endl;

    std::ostringstream buf;
    
    for(std::list<interface_info>::iterator it = ii.begin();
	it != ii.end();
	it++) {
	buf << it->interface << ":" << it->delay << ":" 
	    << it->filter << "\n";
    }
    
    response(201, "Interfaces list follows.", buf.str());

}

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

void connection::cmd_add_interface(const std::vector<std::string>& lst)
{

    if (lst.size() != 3 && lst.size() != 4) {
	error(301, "Usage: add_interface <if> <del> [<fltr>]");
	return;
    }
    
    std::string iface = lst[1];
    int delay;
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

void connection::cmd_remove_interface(const std::vector<std::string>& lst)
{

    if (lst.size() != 3 && lst.size() != 4) {
	error(301, "Usage: remove_interface <if> <del> [<fltr>]");
	return;
    }
    
    std::string iface = lst[1];
    int delay;
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

// ETSI LI connection body, handles a single connection.
void connection::run()
{

    try {

	while (1) {

	    std::string line;

	    try {

		try {
		    s.readline(line);
		} catch (...) {
		    // Socket close, probably.
		    break;
		}

		std::cerr << "control: " << line << std::endl;

		std::vector<std::string> lst;

		tokenise(line, lst);

		if (lst.empty()) {
		    ok(200, "Nothing to do.");
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

		if (lst.front() == "remove_target") {
		    cmd_remove_endpoint(lst);
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

    s.close();

    svc.close_me(this);

}


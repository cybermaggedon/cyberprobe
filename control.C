
#include "control.h"

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

void connection::ok(const std::string& resp)
{
    std::ostringstream buf;
    buf << "OK " << resp.size() << "\n";
    s.write(buf.str());
    s.write(resp);
}

void connection::error(const std::string& resp)
{
    std::ostringstream buf;
    buf << "ERROR " << resp.size() << "\n";
    s.write(buf.str());
    s.write(resp);
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
		    ok("Nothing to do.\n");
		    continue;
		}
		    

		if (lst.front() == "endpoints") {

		    std::list<sender_info> si;
		    d.get_endpoints(si);

		    std::ostringstream buf;

		    for(std::list<sender_info>::iterator it = si.begin();
			it != si.end();
			it++) {
			buf << it->hostname << ":" << it->port << ":" 
			    << it->type << ":" << it->description << "\n";
		    }

		    ok(buf.str());
		    continue;

		} 
  
		if (lst.front() == "targets") {

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

		    ok(buf.str());
		    continue;

		} 
  
		if (lst.front() == "add_target") {

		    if (lst.size() != 4) {
			error("Usage: add_target <liid> <class> <address>\n");
			continue;
		    }

		    std::string liid = lst[1];
		    std::string cls = lst[2];
		    
		    if (cls == "ipv4") {
			
			try {
			    tcpip::ip4_address a4(lst[3]);
			    d.add_target(a4, liid);
			} catch (...) {
			    error("Failed to parse address.\n");
			    continue;
			}

			ok("Added target.\n");
			continue;

		    }

		    if (cls == "ipv6") {
			
			try {
			    tcpip::ip6_address a6(lst[3]);
			    d.add_target(a6, liid);
			} catch (...) {
			    error("Failed to parse address.\n");
			    continue;
			}

			ok("Added target.\n");
			continue;

		    }

		    error("Address class not recognised.\n");

		    continue;

		} 

		if (lst.front() == "remove_target") {

		    if (lst.size() != 3) {
			error("Usage: add_target <class> <address>\n");
			continue;
		    }

		    std::string cls = lst[1];
		    
		    if (cls == "ipv4") {
			
			try {
			    tcpip::ip4_address a4(lst[2]);
			    d.remove_target(a4);
			} catch (...) {
			    error("Failed to parse address.\n");
			    continue;
			}

			ok("Removed target.\n");
			continue;

		    }

		    if (cls == "ipv6") {
			
			try {
			    tcpip::ip6_address a6(lst[2]);
			    d.remove_target(a6);
			} catch (...) {
			    error("Failed to parse address.\n");
			    continue;
			}

			ok("Remove target.\n");
			continue;

		    }

		    error("Address class not recognised.\n");

		    continue;

		} 

		error("Command not known.\n");

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

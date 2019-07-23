
#include "control.h"
#include "management.h"
#include "json.h"
#include "parameter.h"

#include <vector>
#include <mutex>

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

    // Called by a connection when it terminates to request tidy-up.
    void service::close_me(connection* c)
    {

        // Just puts the connection on a list to clear up.
        std::lock_guard<std::mutex> lock(close_me_mutex);
        close_mes.push(c);

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
                std::shared_ptr<tcpip::stream_socket> cn = svr.accept();

                // Spawn a connection thread.
                connection* c = new connection(cn, d, *this, sp);
                connections.push_back(c);
                c->start();

            }

            // Tidy up any connections which need clearing up.
            std::lock_guard<std::mutex> lock(close_me_mutex);

            while (!close_mes.empty()) {

                // Wait for thread to close.
                close_mes.front()->join();

                // Delete resource.
                delete close_mes.front();
                connections.remove(close_mes.front());

                close_mes.pop();
            }

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

        while (!left.empty()) {

            left.erase(0, left.find_first_not_of(" \t"));
	
            int pos = left.find_first_of(" \t");
            if (pos != -1) {

                tok.push_back(left.substr(0, pos));
                left.erase(0, pos+1);

            } else if (!left.empty()) {

                tok.push_back(left);
                left.clear();

            }

        }

    }

    // Return an OK response (should be status=200).
    void connection::ok(int status, const std::string& msg)
    {
     json j = {
            {"status", status},
            {"message", msg}
        };

        std::string e = j.dump();
        s->write(std::to_string(e.size()) + "\n");
        s->write(e);

        std::cerr << "Reply: " << status << " " << msg << std::endl;

    }

    // Return an ERROR response (should be status=3xx or 5xx).
    void connection::error(int status, const std::string& msg)
    {
        json j = {
            {"status", status},
            {"message", msg}
        };

        std::string e = j.dump();
        s->write(std::to_string(e.size()) + "\n");
        s->write(e);

        std::cerr << "Reply: " << status << " " << msg << std::endl;

    }

    // Return an OK response with payload (should be status=201).
    void connection::response(const json& j)
    {

        std::string e = j.dump();
        s->write(std::to_string(e.size()) + "\n");
        s->write(e);

        std::cerr << "Reply: " << e << std::endl;

    }

    // 'endpoints' command.
    void connection::cmd_endpoints()
    {

        std::list<endpoint::spec> si;
        d.get_endpoints(si);

        json j(si);
//        response(201, "Endpoints list follows.", j.dump());

    }

    // 'interfaces' command.
    void connection::cmd_interfaces()
    {

        std::list<interface::spec> ii;
    
        try {
            d.get_interfaces(ii);
        } catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        json j = {
            {"status", 201},
            {"message", "Interfaces list."},
            {"interfaces", ii}
        };

        response(j);

    }

    // 'parameters' command.
    void connection::cmd_parameters()
    {

        std::list<parameter::spec> p;
    
        d.get_parameters(p);

        json j(p);
//        response(201, "Paramter list follows.", j.dump());

    }

    // 'targets' command.
    void connection::cmd_targets()
    {

        std::list<target::spec> lst;
		    
        d.get_targets(lst);

        json j(lst);
//        response(201, "Targets list follows,", j.dump());

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
            interface::spec sp;
            sp.ifa = iface;
            sp.filter = filter;
            sp.delay = delay;
            d.add_interface(sp);
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
         interface::spec sp;
            sp.ifa = iface;
            sp.filter = filter;
            sp.delay = delay;
            d.add_interface(sp);
            d.remove_interface(sp);
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

        std::string device = lst[1];
        std::string cls = lst[2];

        if (cls == "ipv4") {
	
            try {

                tcpip::ip4_address a4;
                unsigned int mask;
                tcpip::ip4_address::parse(lst[3], a4, mask);

                // FIXME: Can't control network parameter.
                target::spec sp;
                sp.addr = a4;
                sp.mask = mask;
                sp.universe = sp.IPv4;
                sp.device = device;
                sp.network = "";
                d.add_target(sp);

            } catch (...) {
                error(302, "Failed to parse address.");
                return;
            }
	
            ok(200, "Added target.");
            return;
	
        }
    
        if (cls == "ipv6") {
	
            try {
                unsigned int mask;
                tcpip::ip6_address a6;
                tcpip::ip6_address::parse(lst[3], a6, mask);

                // FIXME: Can't control network parameter.
                target::spec sp;
                sp.addr6 = a6;
                sp.mask = mask;
                sp.universe = sp.IPv4;
                sp.device = device;
                sp.network = "";
                d.add_target(sp);

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
                unsigned int mask;
                tcpip::ip4_address a4;
                tcpip::ip4_address::parse(lst[2], a4, mask);

                // FIXME: Using the spec seems kludgy?  It's not completely
                // filled out.
                target::spec sp;
                sp.addr = a4;
                sp.mask = mask;
                sp.universe = sp.IPv4;

                d.remove_target(sp);
            } catch (...) {
                error(302, "Failed to parse address.");
                return;
            }

            ok(200, "Removed target.");
            return;

        }

        if (cls == "ipv6") {
	
            try {

                unsigned int mask;
                tcpip::ip6_address a6;
                tcpip::ip6_address::parse(lst[2], a6, mask);

                // FIXME: Using the spec seems kludgy?  It's not completely
                // filled out.
                target::spec sp;
                sp.addr6 = a6;
                sp.mask = mask;
                sp.universe = sp.IPv6;

                d.remove_target(sp);

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

        if (lst.size() != 5) {
            error(301, "Usage: add_endpoint <host> <port> <type> <transport>");
            return;
        }
    
        const std::string& host = lst[1];
        int port;
        std::istringstream buf(lst[2]);
        buf >> port;
        const std::string& type = lst[3];
        const std::string& transport = lst[4];
    
        try {

            // FIXME: Allow parameters to be added.
            endpoint::spec ep;
            ep.hostname = host;
            ep.port = port;
            ep.type = type;
            ep.transport = transport;
            d.add_endpoint(ep);
            ok(200, "Added endpoint.");
        } catch (...) {
            error(500, "Failed to add endpoint.");
        }

    }

    // 'remove_endpoint' command.
    void connection::cmd_remove_endpoint(const std::vector<std::string>& lst)
    {

        if (lst.size() != 5) {
            error(301, "Usage: remove_endpoint <host> <port> <type> <transport>");
            return;
        }
    
        const std::string host = lst[1];
        int port;
        std::istringstream buf(lst[2]);
        buf >> port;
        const std::string type = lst[3];
        const std::string transport = lst[4];
    
        try {
            // FIXME: Allow parameters to be added.
            endpoint::spec ep;
            ep.hostname = host;
            ep.port = port;
            ep.type = type;
            ep.transport = transport;
            d.remove_endpoint(ep);
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
            parameter::spec sp(key, val);
            d.add_parameter(sp);
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
            // FIXME: Looks ugly?
            parameter::spec sp;
            sp.key = key;
            d.remove_parameter(sp);
            ok(200, "Removed parameter.");
        } catch (...) {
            error(500, "Failed to remove parameter.");
        }

    }

    // 'auth' command.
    void connection::cmd_auth(const json& j)
    {

        try {

            if (j["username"].get<std::string>() == sp.username &&
                j["password"].get<std::string>() == sp.password) {
                auth = true;
                ok(200, "Authenticated.");
                return;
            }

            error(331, "Authentication failure.");
            return;

        } catch (std::exception& e) {
            error(500, e.what());
        }

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

//        response(201, "Help information follows.", buf.str());
    }

    // connection body, handles a single connection.
    void connection::run()
    {

        try {

            while (running) {

                std::string line;

                try {

                    // Keep checking the loop condition if we're idle.
                    bool activ = s->poll(1.0);
                    if (!activ) continue;

                    // Get the next command.
                    try {
                        s->readline(line);
                    } catch (...) {
                        // Socket close, probably.
                        break;
                    }

                    std::cerr << "Command: " << line << std::endl;

                    json j;
                    try {
                        std::cerr << line << std::endl;
                        j = json::parse(line);
                    } catch (...) {
                        error(301, "Could not parse JSON");
                        continue;
                    }

                    if (j["action"].is_null()) {
                        error(301, "Must specify 'action'");
                        continue;
                    }

                    if (j["action"] == "help") {
                        error(305, "Help not implemented.");
                        continue;
                    }

                    if (j["action"] == "auth") {
                        cmd_auth(j);
                        continue;
                    }

                    if (j["action"] == "get-interfaces") {
                        cmd_interfaces();
                        continue;
                    }

#ifdef ASDASD

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

#endif

                    error(301, "Command not known.");

                } catch (...) {
                    break;
                }

            }

        } catch (std::exception& e) {
            std::cerr << e.what() << std::endl;
        }

        // Close the connection.
        s->close();

        // Add me to the tidy-up-list.
        svc.close_me(this);

    }

};


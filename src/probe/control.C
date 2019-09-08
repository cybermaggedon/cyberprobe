
#include <cyberprobe/probe/control.h>
#include <cyberprobe/probe/management.h>
#include <cyberprobe/probe/parameter.h>
#include <nlohmann/json.h>

#include <vector>
#include <mutex>

namespace cyberprobe {

namespace probe {

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

    }

    // Return an OK response with payload (should be status=201).
    void connection::response(const json& j)
    {

        std::string e = j.dump();
        s->write(std::to_string(e.size()) + "\n");
        s->write(e);

    }

    // 'endpoints' command.
    void connection::cmd_endpoints()
    {

        std::list<endpoint::spec> es;
    
        try {
            d.get_endpoints(es);
        } catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        json j = {
            {"status", 201},
            {"message", "Endpoints list."},
            {"endpoints", es}
        };

        response(j);

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

        std::list<parameter::spec> ii;
    
        try {
            d.get_parameters(ii);
        } catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        json j = {
            {"status", 201},
            {"message", "Parameters list."},
            {"parameters", ii}
        };

        response(j);

    }

    // 'targets' command.
    void connection::cmd_targets()
    {

        std::list<target::spec> ii;
    
        try {
            d.get_targets(ii);
        } catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        json j = {
            {"status", 201},
            {"message", "Target list."},
            {"targets", ii}
        };

        response(j);

    }

    // 'add_interface' command.
    void connection::cmd_add_interface(const json &j)
    {

        try {

            interface::spec sp;
            j["interface"].get_to(sp);
            d.add_interface(sp);
        } catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Interface added.");

    }

    // 'remove_interface' command.
    void connection::cmd_remove_interface(const json& j)
    {

        try {

            interface::spec sp;
            j["interface"].get_to(sp);
            d.remove_interface(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Interface removed.");
    
    }

    // 'add_target' command.
    void connection::cmd_add_target(const json& j)
    {

        try {
            target::spec sp;
            j["target"].get_to(sp);
            d.add_target(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Target added.");
    
    }

    // 'remove_target' command.
    void connection::cmd_remove_target(const json& j)
    {

        try {
            target::spec sp;
            j["target"].get_to(sp);
            d.remove_target(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Target removed.");
    
    }

    // 'add_endpoint' command.
    void connection::cmd_add_endpoint(const json& j)
    {

        try {
            endpoint::spec sp;
            j["endpoint"].get_to(sp);
            d.add_endpoint(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Endpoint added.");
    
    }

    // 'remove_endpoint' command.
    void connection::cmd_remove_endpoint(const json& j)
    {

        try {
            endpoint::spec sp;
            j["endpoint"].get_to(sp);
            d.remove_endpoint(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Endpoint removed.");
    
    }

    // 'add_endpoint' command.
    void connection::cmd_add_parameter(const json& j)
    {

        try {

            parameter::spec sp;
            j["parameter"].get_to(sp);
            d.add_parameter(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Parameter added.");
    
    }

    // 'add_endpoint' command.
    void connection::cmd_remove_parameter(const json& j)
    {

        try {

            parameter::spec sp;
            j["parameter"].get_to(sp);
            d.remove_parameter(sp);
        }  catch (std::exception& e) {
            error(500, e.what());
            return;
        }

        ok(200, "Parameter removed.");
    
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

            sleep(1);
            error(331, "Authentication failure.");
            return;

        } catch (std::exception& e) {
            error(500, e.what());
        }

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

                    json j;
                    try {
                        j = json::parse(line);
                    } catch (...) {
                        error(301, "Could not parse JSON");
                        continue;
                    }

                    if (j["action"].is_null()) {
                        error(301, "Must specify 'action'");
                        continue;
                    }

                    if (j["action"] == "auth") {
                        cmd_auth(j);
                        continue;
                    }

                    if (j["action"] == "quit") {
                        ok(200, "Tra, then.");
                        break;
                    }

                    // This is the authentication gate.  Can only do 'help' and
                    // 'auth' until we've authenticated.
                    if (!auth) {
                        error(330, "Authenticate before continuing.");
                        continue;
                    }

                    if (j["action"] == "get-interfaces") {
                        cmd_interfaces();
                        continue;
                    }

                    if (j["action"] == "get-targets") {
                        cmd_targets();
                        continue;
                    } 

                    if (j["action"] == "get-endpoints") {
                        cmd_endpoints();
                        continue;
                    } 
                    
                    if (j["action"] == "get-parameters") {
                        cmd_parameters();
                        continue;
                    } 

                    if (j["action"] == "add-interface") {
                        cmd_add_interface(j);
                        continue;
                    }                     

                    if (j["action"] == "remove-interface") {
                        cmd_remove_interface(j);
                        continue;
                    } 

                    if (j["action"] == "add-target") {
                        cmd_add_target(j);
                        continue;
                    }                     

                    if (j["action"] == "remove-target") {
                        cmd_remove_target(j);
                        continue;
                    } 

                    if (j["action"] == "add-endpoint") {
                        cmd_add_endpoint(j);
                        continue;
                    }                     

                    if (j["action"] == "remove-endpoint") {
                        cmd_remove_endpoint(j);
                        continue;
                    } 

                    if (j["action"] == "add-parameter") {
                        cmd_add_parameter(j);
                        continue;
                    }                     

                    if (j["action"] == "remove-parameter") {
                        cmd_remove_parameter(j);
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
        s->close();

        // Add me to the tidy-up-list.
        svc.close_me(this);

    }

}

}

}


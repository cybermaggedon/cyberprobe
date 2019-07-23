
#ifndef CONTROL_H
#define CONTROL_H

#include <vector>
#include <queue>
#include <mutex>
#include <thread>

#include <cybermon/socket.h>
#include <cybermon/specification.h>
#include <cybermon/resource.h>

#include "management.h"
#include "json.h"

namespace control {
    
    using json = nlohmann::json;
    
    // Management interface specification.
    class spec : public cybermon::specification {
    public:

	// Type is 'control'.
	virtual std::string get_type() const { return "control"; }

	// Endpoint parameters.
	int port;
	std::string username;
	std::string password;

	// Constructors.
	spec() {}
	spec(unsigned short port, const std::string& username, 
             const std::string& password) {
	    this->port = port; this->username = username; 
	    this->password = password;
	}

	// Hash is form host:port.
	virtual std::string get_hash() const { 
	    std::ostringstream buf;
	    buf << port << ":" << username << ":" << password;
	    return buf.str();
	}

    };
    
    class service;

    // A single connection to the management interface.
    class connection {

    private:

	// Connected socket.
	std::shared_ptr<tcpip::stream_socket> s;

	// The thing that actually implements the management commands.
	management& d;

	// True = running.
	bool running;

	// The management service which spawned this connection.
	service& svc;

	// Resource specification.
	spec& sp;
	
	// True = A successful authentication.
	bool auth;

	// Methods which implement the commands.
	void cmd_endpoints();
	void cmd_targets();
	void cmd_interfaces();
	void cmd_parameters();
	void cmd_add_interface(const json& j);
	void cmd_remove_interface(const json& j);
	void cmd_add_target(const json& j);
	void cmd_remove_target(const json& j);
	void cmd_add_endpoint(const json& j);
	void cmd_remove_endpoint(const json& j);
	void cmd_auth(const json& j);
	void cmd_add_parameter(const json& j);
	void cmd_remove_parameter(const json& j);

	// OK response.
	void ok(int status, const std::string& msg);

	// Error response.
	void error(int status, const std::string& msg);

	// Response with payload.
        void response(const json& j);

	// Thread body.
	virtual void run();

	std::thread* thr;

    public:

	// Constructor.
        connection(std::shared_ptr<tcpip::stream_socket> s, management& d,
		   service& svc, spec& sp) :
            s(s), d(d), svc(svc), sp(sp) {
	    running = true;
	    auth = false;
	    thr = 0;
	}

	virtual void start() {
	    thr = new std::thread(&connection::run, this);
	}

	// Desctructor.
	virtual ~connection() {
	    delete thr;
	}

	virtual void join() {
	    if (thr)
		thr->join();
	}

	virtual void stop() {
	    running = false;
	}

    };

    // Management service.
    class service : public cybermon::resource {

    private:
	
	// TCP socket, accepting connections.
	tcpip::tcp_socket svr;

	// Resource specification.
	spec& sp;

	// Thing which implements the management commands.
	management& d;

	// True = running, false = closing down.
	bool running;

	// Lock for threads list.
	std::mutex close_me_mutex;

	// Connection threads.
	std::queue<connection*> close_mes;

	std::list<connection*> connections;

	std::thread* thr;

    public:

	// Thread body.
	virtual void run();

	// Constructor.
        service(spec& s, management& d) : sp(s), d(d) {
            running = true;
	    thr = 0;
        }

	// Start the thread body.
	virtual void start() {
	    std::cerr << "Starting control on port " << sp.port << std::endl;
	    thr = new std::thread(&service::run, this);
	}

	// Stop.
	virtual void stop() {
	    running = false;
	    std::cerr << "Control on port " << sp.port << " stopped."
		      << std::endl;
	    join();
	}

	virtual void join() {
	    if (thr)
		thr->join();
	}
	
	// Destructor.
	virtual ~service() {
	    delete thr;
	}

	// Called by a connection when it terminates to request tidy-up.
	virtual void close_me(connection* c);
    
    };

    void to_json(json& j, const spec& s);
    
    void from_json(const json& j, spec& s);

};

#endif


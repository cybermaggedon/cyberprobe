
#ifndef CONTROL_H
#define CONTROL_H

#include <vector>
#include <queue>

#include <cybermon/socket.h>
#include <cybermon/thread.h>
#include <cybermon/specification.h>
#include <cybermon/resource.h>

#include "management.h"

namespace control {

    // Management interface specification.
    class spec : public cybermon::specification {
      public:

	// Type is 'control'.
	virtual std::string get_type() const { return "control"; }

	// Endpoint parameters.
	unsigned short port;
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
    class connection : public threads::thread {

      private:

	// Connected socket.
	boost::shared_ptr<tcpip::stream_socket> s;

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
	void cmd_add_interface(const std::vector<std::string>& lst);
	void cmd_remove_interface(const std::vector<std::string>& lst);
	void cmd_add_target(const std::vector<std::string>& lst);
	void cmd_remove_target(const std::vector<std::string>& lst);
	void cmd_add_endpoint(const std::vector<std::string>& lst);
	void cmd_remove_endpoint(const std::vector<std::string>& lst);
	void cmd_help();
	void cmd_auth(const std::vector<std::string>& lst);
	void cmd_add_parameter(const std::vector<std::string>& lst);
	void cmd_remove_parameter(const std::vector<std::string>& lst);

	// Command line tokenisation.
	static void tokenise(const std::string& line, 
			     std::vector<std::string>& tok);

	// OK response.
	void ok(int status, const std::string& msg);

	// Error response.
	void error(int status, const std::string& msg);

	// Response with payload.
	void response(int status, const std::string& msg,
		      const std::string& response);

	// Thread body.
	virtual void run();

      public:

	// Constructor.
        connection(boost::shared_ptr<tcpip::stream_socket> s, management& d,
		   service& svc, spec& sp) : s(s), d(d), svc(svc), sp(sp) {
	    running = true;
	    auth = false;
	}

	virtual void stop() { running = false; }

	// Desctructor.
	virtual ~connection() {}

    };

    // Management service.
    class service : public cybermon::resource, public threads::thread {

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
	threads::mutex close_me_lock;

	// Connection threads.
	std::queue<connection*> close_mes;

	std::list<connection*> connections;

	// Thread body.
	virtual void run();

      public:

	// Constructor.
        service(spec& s, management& d) : sp(s), d(d) {
            running = true;
        }

	// Start the thread body.
	virtual void start() {
	    std::cerr << "Starting control on port " << sp.port << std::endl;
	    threads::thread::start();
	}

	// Stop.
	virtual void stop() {
	    running = false;
	    std::cerr << "Control on port " << sp.port << " stopped."
		      << std::endl;
	    join();
	}

	// Destructor.
	virtual ~service() {}

	// Called by a connection when it terminates to request tidy-up.
	virtual void close_me(connection* c);
    
    };

};

#endif



#ifndef CONTROL_H
#define CONTROL_H

#include <vector>

#include "socket.h"
#include "thread.h"
#include "targeting.h"
#include "specification.h"
#include "resource.h"

namespace control {

    class spec : public specification {
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

    class connection : public threads::thread {

      private:
	tcpip::tcp_socket s;
	targeting& d;
	bool running;
	service& svc;

      public:

	static void tokenise(const std::string& line, 
			     std::vector<std::string>& tok);

	void ok(const std::string& response);

	void error(const std::string& response);

        connection(tcpip::tcp_socket s, targeting& d,
		 service& svc) : s(s), d(d), svc(svc) {
	    running = true;
	}
	virtual ~connection() {}
	virtual void run();
    };

    class service : public resource, public threads::thread {

      private:
	tcpip::tcp_socket svr;
	targeting& d;
	spec& sp;
	bool running;

	threads::mutex close_me_lock;
	std::queue<connection*> close_mes;

      public:
        service(spec& s, targeting& d) : sp(s), d(d) {
            running = true;
        }

	virtual void start() {
	    std::cerr << "Starting control on port " << sp.port << std::endl;
	    threads::thread::start();
	}

	virtual void stop() {
	    running = false;
	    join();
	}

	virtual ~service() {}
	virtual void run();
	virtual void close_me(connection* c);
    
    };

};

#endif



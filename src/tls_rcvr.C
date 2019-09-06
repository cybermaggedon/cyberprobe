
#include <cyberprobe/network/socket.h>

#include <iostream>
#include <memory>
#include <queue>
#include <vector>
#include <fstream>
#include <thread>
#include <mutex>

#include <stdlib.h>

using namespace cyberprobe::tcpip;

class receiver;

class connection {

private:
    std::shared_ptr<stream_socket> s;
    receiver &r;
    bool running;
    std::ofstream out;

    std::thread* thr;

public:
    connection(std::shared_ptr<stream_socket> s, receiver& r,
	       std::string fname) : s(s), r(r) {
	running = true;
	std::cout << "Writing to " << fname << std::endl;
	out.open(fname.c_str());
    }
    virtual ~connection() {}
    virtual void run();

    virtual void start() {
	thr = new std::thread(&connection::run, this);
    }
    
    virtual void stop() {
	running = false;
	join();
    }
    
    virtual void join() {
	if (thr)
	    thr->join();
    }

};

class receiver {

private:
    bool running;
    std::string base;
    int oneup;

    std::shared_ptr<stream_socket> svr;

    std::mutex close_me_mutex;
    std::queue<connection*> close_mes;

    std::thread* thr;

public:
    receiver(int port, const std::string& base,
	     const std::string& key, const std::string& cert,
	     const std::string& ca) : base(base) {
	running = true;
	ssl_socket* ssl = new ssl_socket;
	ssl->use_key_file(key);
	ssl->use_certificate_file(cert);
	ssl->use_certificate_chain_file(ca);
	std::shared_ptr<stream_socket> sock(ssl);
	svr = sock;
	svr->bind(port);
	oneup = 0;
    }

    virtual ~receiver() {}
    virtual void run();
    virtual void close_me(connection* c);

    virtual void start() {
	thr = new std::thread(&receiver::run, this);
    }
    
    virtual void stop() {
	running = false;
	join();
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
};

void receiver::run()
{

    try {

	svr->listen();

	while (running) {

	    bool activ = svr->poll(1.0);

	    if (activ) {

		std::shared_ptr<stream_socket> cn;

		try {
		    cn = svr->accept();
		} catch (...) {
		    continue;
		}

		std::ostringstream buf;
		buf << base << oneup++;

		connection* c = new connection(cn, *this, buf.str());

		c->start();

	    }

	    std::lock_guard<std::mutex> lock(close_me_mutex);

	    while (!close_mes.empty()) {
		close_mes.front()->join();
		delete close_mes.front();
		close_mes.pop();
	    }

	}

    } catch (std::exception& e) {

	std::cerr << "Exception: " << e.what() << std::endl;
	return;

    }

}

void connection::run()
{

    try {

	while (1) {

	    std::vector<unsigned char> buffer;
	    int ret = s->read(buffer, 256);
	    std::cerr << ret << std::endl;
	    if (ret <= 0) break;
	    
	    out.write(reinterpret_cast<char*>(buffer.data()), ret);

	}
	
    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

    out.close();

    s->close();

    r.close_me(this);

}

void receiver::close_me(connection* c)
{
    std::lock_guard<std::mutex> lock(close_me_mutex);
    close_mes.push(c);
}


int main(int argc, char** argv)
{

    if (argc != 5) {
	std::cerr << "Usage:\n\tstream-rcvr <port> <key> <cert> <ca>\n";
	return 1;
    }
    
    try {

	std::ostringstream base;
	base << "stream-" << getpid() << "-";
	
	receiver r(atoi(argv[1]), base.str(), argv[2], argv[3], argv[4]);
	r.run();
	
    } catch (std::exception& e) {
	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;
    }

    return 0;

}


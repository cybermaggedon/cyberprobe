
#include <cybermon/socket.h>
#include <iostream>
#include <boost/shared_ptr.hpp>
#include <cybermon/thread.h>
#include <queue>
#include <vector>
#include <fstream>
#include <stdlib.h>

class receiver;

class connection : public threads::thread {

  private:
    boost::shared_ptr<tcpip::stream_socket> s;
    receiver &r;
    bool running;
    std::ofstream out;

  public:
    connection(boost::shared_ptr<tcpip::stream_socket> s, receiver& r,
	       std::string fname) : s(s), r(r) {
	running = true;
	std::cout << "Writing to " << fname << std::endl;
	out.open(fname);
    }
    virtual ~connection() {}
    virtual void run();
};

class receiver : public threads::thread {

  private:
    bool running;
    std::string base;
    int oneup;

    boost::shared_ptr<tcpip::stream_socket> svr;

    threads::mutex close_me_lock;
    std::queue<connection*> close_mes;

  public:
    receiver(int port, const std::string& base) : base(base) {
	running = true;
	boost::shared_ptr<tcpip::stream_socket> sock(new tcpip::tcp_socket);
	svr = sock;
	svr->bind(port);
	oneup = 0;
    }

    virtual ~receiver() {}
    virtual void run();
    virtual void close_me(connection* c);
    
};

void receiver::run()
{

    try {

	svr->listen();

	while (running) {

	    bool activ = svr->poll(1.0);

	    if (activ) {

		boost::shared_ptr<tcpip::stream_socket> cn;

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

	    close_me_lock.lock();

	    while (!close_mes.empty()) {
		close_mes.front()->join();
		delete close_mes.front();
		close_mes.pop();
	    }
	    close_me_lock.unlock();

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
	    int ret = s->read(buffer, 1024);
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
    close_me_lock.lock();
    close_mes.push(c);
    close_me_lock.unlock();
}


int main(int argc, char** argv)
{

    if (argc != 2) {
	std::cerr << "Usage:\n\tstream-rcvr <port>\n";
	return 1;
    }
    
    try {

	std::ostringstream base;
	base << "stream-" << getpid() << "-";
	
	receiver r(atoi(argv[1]), base.str());
	r.run();
	
    } catch (std::exception& e) {
	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;
    }

    return 0;

}


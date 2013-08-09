
/****************************************************************************

ETSI LI test receiver.  Usage:

  etsi_rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include <iostream>
#include <map>

#include "analyser.h"
#include "monitor.h"
#include "etsi_li.h"
#include "thread.h"
#include "packet_capture.h"

class cybermon : public monitor {
private:
    threads::mutex lock;
    analyser::engine& an;

public:

    // Maps LIID to context.
    std::map<std::string, analyser::context&> contexts;

    typedef std::vector<unsigned char>::iterator iter;
    cybermon(analyser::engine& an) : an(an) {}
    virtual void operator()(const std::string& liid, const iter& s, 
			    const iter& e);
    void discovered(const std::string& liid,
		    const tcpip::address& addr);

};

void cybermon::discovered(const std::string& liid,
			  const tcpip::address& addr)
{

    lock.lock();

    if (contexts.find(liid) == contexts.end()) {
	analyser::context& c = an.create_context(liid);
	contexts.insert(std::pair<std::string,analyser::context&>(liid, c));
    }

    // FIXME: You done nothing with the address.

    std::cerr << "Target " << liid << " discovered on IP " << addr
	      << std::endl;
    
    lock.unlock();

}

void cybermon::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{
    lock.lock();

    if (contexts.find(liid) == contexts.end()) {
	analyser::context& c = an.create_context(liid);
	contexts.insert(std::pair<std::string,analyser::context&>(liid, c));
    }
    
    analyser::context& c = contexts.find(liid)->second;

    lock.unlock();

    an.process(c, s, e);

}

int main(int argc, char** argv)
{
    
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    analyser::engine an;

    cybermon m(an);

    etsi_li::receiver r(port, m);

    r.start();

    r.join();

}



/****************************************************************************

Monitor thing.

  cybermon <portnum> | tcpdump -n -r-

****************************************************************************/

#include <iostream>
#include <map>

#include "analyser.h"
#include "monitor.h"
#include "etsi_li.h"
#include "thread.h"
#include "packet_capture.h"
#include "flow.h"
#include "hexdump.h"
#include "context.h"

class obs : public analyser::engine {
public:
    void data(const analyser::context_ptr f, const analyser::pdu_iter& s, 
	      const analyser::pdu_iter& e);
};

void obs::data(const analyser::context_ptr f, const analyser::pdu_iter& s, 
	       const analyser::pdu_iter& e)
{

    analyser::context_ptr p = f;

    std::string liid;
    analyser::address target_address;

    analyser::address src, dest;
    
    get_root_info(f, liid, target_address);
    get_network_info(f, src, dest);

    std::cerr << "Target " << liid << " ";

    if (src == target_address)
	std::cerr << " - data from target";

    if (dest == target_address)
	std::cerr << " - data to target";

    std::cout << std::endl;

    describe(f, std::cout);
    std::cout << std::endl;

    hexdump::dump(s, e, std::cout);

    std::cout << std::endl;
}

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

    analyser::context_ptr c = an.get_root_context(liid);
    analyser::target_context* tc = 
	dynamic_cast<analyser::target_context*>(c.get());

    tc->set_target_address(addr);

    std::cerr << "Target " << liid << " discovered on IP " << addr
	      << std::endl << std::endl;

}

void cybermon::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{

    analyser::context_ptr c = an.get_root_context(liid);

    try {
	an.process(c, s, e);
    } catch (std::exception& e) {
	std::cerr << "Packet failed: " << e.what() << std::endl;
    }

}

int main(int argc, char** argv)
{
    
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    obs an;

    cybermon m(an);

    etsi_li::receiver r(port, m);

    r.start();

    r.join();

}



/****************************************************************************

ETSI LI test receiver.  Usage:

  etsi_rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include "packet.h"
#include "etsi_li.h"

#include "thread.h"
#include "packet_capture.h"

class output : public packet_processor {
private:
    pcap_writer& p;
    threads::mutex lock;
public:
    output(pcap_writer& p) : p(p) {}
    virtual void operator()(const std::string& liid,
			    const std::vector<unsigned char>::iterator& s,
			    const std::vector<unsigned char>::iterator& e) {
	lock.lock();
	p.write(s, e);
	lock.unlock();
    }

    void discovered(const std::string& liid,
		    const tcpip::address& addr) {
	std::cerr << "Target " << liid << " discovered on IP " << addr
		  << std::endl;
    }

};

int main(int argc, char** argv)
{
    
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    pcap_writer p;

    output o(p);

    etsi_li::receiver r(port, o);

    r.start();

    r.join();

}


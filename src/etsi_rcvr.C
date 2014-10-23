
/****************************************************************************

ETSI LI test receiver.  Usage:

  etsi_rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include <cybermon/monitor.h>
#include <cybermon/etsi_li.h>
#include <cybermon/thread.h>
#include <cybermon/packet_capture.h>

class output : public monitor {
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

    void target_up(const std::string& liid,
		    const tcpip::address& addr) {
	std::cerr << "Target " << liid << " discovered on IP " << addr
		  << std::endl;
    }

    void target_down(const std::string& liid) {
	std::cerr << "Target " << liid << " offline. " << std::endl;
    }

};

int main(int argc, char** argv)
{
    
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    pcap_writer p;

    output o(p);

    cybermon::etsi_li::receiver r(port, o);

    r.start();

    r.join();

}


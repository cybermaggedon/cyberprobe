
/****************************************************************************

ETSI LI test receiver.  Usage:

  etsi-rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include <cyberprobe/analyser/monitor.h>
#include <cyberprobe/stream/etsi_li.h>
#include <cyberprobe/pkt_capture/packet_capture.h>

using namespace cyberprobe::etsi_li;
using namespace cyberprobe;
using namespace cyberprobe::analyser;

class output : public monitor {
private:
    pcap::writer& p;
    std::mutex mutex;
public:
    output(pcap::writer& p) : p(p) {}
    virtual void operator()(const std::string& liid,
			    const std::string& network,
                            protocol::pdu_slice s) {
	std::lock_guard<std::mutex> lock(mutex);
	p.write(s.start, s.end);
    }

    void target_up(const std::string& liid,
		   const std::string& network,
		   const tcpip::address& addr,
		   const timeval& tv) {
	std::cerr << "Target " << liid << " discovered on IP " << addr
		  << std::endl;
    }

    void target_down(const std::string& liid,
		     const std::string& network,
		     const timeval& tv) {
	std::cerr << "Target " << liid << " offline. " << std::endl;
    }

};

int main(int argc, char** argv)
{
    
    if (argc != 2) {
	std::cerr << "Usage:" << std::endl
		  << "\tetsi-rcvr <port>" << std::endl;
	exit(1);
    }

    try {

	std::istringstream buf(argv[1]);
	int port;
	buf >> port;

        pcap::writer p;

	output o(p);

	etsi_li::receiver r(port, o);

	r.start();
	r.join();

    } catch (std::exception& e) {
	std::cerr << "Exception: " << e.what() << std::endl;
	exit(1);
    }

}


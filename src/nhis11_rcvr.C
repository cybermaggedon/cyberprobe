
/****************************************************************************

NHIS 1.1 test receiver.  Usage:

  nhis11-rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/protocol/address.h>
#include <cyberprobe/analyser/monitor.h>
#include <cyberprobe/stream/nhis11.h>
#include <cyberprobe/pkt_capture/packet_capture.h>

#include <thread>
#include <mutex>

#include <getopt.h>

using namespace cyberprobe;

class output : public analyser::monitor {
private:
    pcap::writer& p;
    std::mutex mutex;
public:
    output(cyberprobe::pcap::writer& p) : p(p) {}
    virtual void operator()(const std::string& liid,
			    const std::string& network,
                            protocol::pdu_slice s) {
        std::lock_guard<std::mutex> lock(mutex);
	p.write(s.start, s.end);
    }

    // These events aren't trigger by NHIS 1.1.
    void target_up(const std::string& liid, const std::string& net,
		   const tcpip::address& addr, const timeval& tv) {}
    void target_down(const std::string& liid, const std::string& net,
		     const timeval& tv) {}

};

int main(int argc, char** argv)
{

    if (argc != 2) {
	std::cerr << "Usage:" << std::endl
		  << "\tnhis11-rcvr <port>" << std::endl;
	exit(1);
    }

    try {

	std::istringstream buf(argv[1]);
	int port;
	buf >> port;

        cyberprobe::pcap::writer p;

	output o(p);

	cyberprobe::nhis11::receiver r(port, o);

	r.start();
	r.join();

    } catch (std::exception& e) {

	std::cout << "Exception: " << e.what() << std::endl;

    }

}


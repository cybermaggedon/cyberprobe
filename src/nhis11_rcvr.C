
/****************************************************************************

NHIS 1.1 test receiver.  Usage:

  nhis11-rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include <cybermon/monitor.h>
#include <cybermon/nhis11.h>
#include <cybermon/packet_capture.h>

#include <thread>
#include <mutex>

#include <getopt.h>

class output : public cybermon::monitor {
private:
    pcap_writer& p;
    std::mutex lock;
public:
    output(pcap_writer& p) : p(p) {}
    virtual void operator()(const std::string& liid,
			    const std::string& network,
			    std::vector<unsigned char>::const_iterator s,
			    std::vector<unsigned char>::const_iterator e,
			    const timeval& tv, cybermon::direction d) {
	lock.lock();
	p.write(s, e);
	lock.unlock();
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

	pcap_writer p;

	output o(p);

	cybermon::nhis11::receiver r(port, o);

	r.start();
	r.join();

    } catch (std::exception& e) {

	std::cout << "Exception: " << e.what() << std::endl;

    }

}



/****************************************************************************

NHIS 1.1 test receiver.  Usage:

  nhis11_rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include <cybermon/monitor.h>
#include <cybermon/nhis11.h>
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

    // These events aren't trigger by NHIS 1.1.
    void target_up(const std::string& liid,
		   const tcpip::address& addr) {}
    void target_down(const std::string& liid) {}

};

int main(int argc, char** argv)
{
    
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    pcap_writer p;

    output o(p);

    cybermon::nhis11::receiver r(port, o);

    r.start();

    r.join();

}


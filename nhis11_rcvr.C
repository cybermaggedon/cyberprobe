
/****************************************************************************

NHIS 1.1 test receiver.  Usage:

  nhis11_rcvr <portnum> | tcpdump -n -r-

****************************************************************************/

#include "monitor.h"
#include "nhis11.h"

#include "thread.h"
#include "packet_capture.h"

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

    nhis11::receiver r(port, o);

    r.start();

    r.join();

}


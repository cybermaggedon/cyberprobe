
/****************************************************************************

****************************************************************************
*** OVERVIEW
****************************************************************************

Simple monitor.  Takes ETSI streams from cyberprobe, and reports on various
occurances.

Usage:

    cyberprobe <port-number>

****************************************************************************/

#include <iostream>
#include <iomanip>
#include <map>

#include "engine.h"
#include "monitor.h"
#include "etsi_li.h"
#include "thread.h"
#include "packet_capture.h"
#include "flow.h"
#include "hexdump.h"
#include "context.h"
#include "cybermon-lua.h"

// My observation engine.  Uses the analyser engine, takes the data
// events and keep tabs on how much data has flowed out to attackers.
class obs : public analyser::engine {
private:
    analyser::cybermon_lua cml;

public:

    obs(const std::string& path) : cml(path) {}

    // Map of network address to the amount of data acquired.
    std::map<analyser::address, uint64_t> amounts;

    // Stores the next 'reporting' event for data acquisition by an attacker.
    std::map<analyser::address, uint64_t> next;

    // Connection-orientated.
    virtual void connection_up(const analyser::context_ptr cp) {
	cml.connection_up(*this, cp);
    }

    virtual void connection_down(const analyser::context_ptr cp) {
	cml.connection_down(*this, cp);
    }

    virtual void unrecognised_stream(const analyser::context_ptr cp,
				     analyser::pdu_iter s, 
				     analyser::pdu_iter e) {
	cml.unrecognised_stream(*this, cp, s, e);
    }

    // Connection-less
    virtual void unrecognised_datagram(const analyser::context_ptr cp,
			  analyser::pdu_iter s, analyser::pdu_iter e) {
	cml.unrecognised_datagram(*this, cp, s, e);
    }

    virtual void icmp(const analyser::context_ptr cp,
		      analyser::pdu_iter s, analyser::pdu_iter e) {
	cml.icmp(*this, cp, s, e);
    }

    // HTTP
    virtual void http_request(const analyser::context_ptr cp,
			      const std::string& method,
			      const std::string& url,
			      const analyser::observer::http_hdr_t& hdr,
			      analyser::pdu_iter body_start,
			      analyser::pdu_iter body_end) {
	cml.http_request(*this, cp, method, url, hdr, body_start, body_end);
    }

    virtual void http_response(const analyser::context_ptr cp,
			       unsigned int code,
			       const std::string& status,
			       const analyser::observer::http_hdr_t& hdr,
			       const std::string& url,
			       analyser::pdu_iter body_start,
			       analyser::pdu_iter body_end) {
	cml.http_response(*this, cp, code, status, hdr, url, 
			  body_start, body_end);
    }

    // Trigger
    void trigger_up(const std::string& liid, const tcpip::address& a) {
	cml.trigger_up(liid, a);
    }

    void trigger_down(const std::string& liid) {
	cml.trigger_down(liid);
    }

};

// Monitor class, implements the monitor interface to receive data.
class etsi_monitor : public monitor {
private:

    // Analysis engine
    analyser::engine& an;

public:

    // Short-hand for vector iterator.
    typedef std::vector<unsigned char>::iterator iter;

    // Constructor.
    etsi_monitor(analyser::engine& an) : an(an) {}

    // Called when a PDU is received.
    virtual void operator()(const std::string& liid, const iter& s, 
			    const iter& e);

    // Called when attacker is discovered.
    void target_up(const std::string& liid, const tcpip::address& addr);

    // Called when attacker is disconnected.
    void target_down(const std::string& liid);
    
};

// Called when attacker is discovered.
void etsi_monitor::target_up(const std::string& liid,
			 const tcpip::address& addr)
{
    an.target_up(liid, addr);
}

// Called when attacker is discovered.
void etsi_monitor::target_down(const std::string& liid)
{
    an.target_down(liid);
}

// Called when a PDU is received.
void etsi_monitor::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{

    try {

	// Process the PDU
	an.process(liid, s, e);

    } catch (std::exception& e) {

	// Processing failure event.
	std::cerr << "Packet failed: " << e.what() << std::endl;

    }

}

class pcap_input : public pcap_reader {
private:
    analyser::engine& e;
    int count;

public:
    pcap_input(const std::string& f, analyser::engine& e) : 
	pcap_reader(f), e(e) {
	count = 0;
    }

    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* f);

};


void pcap_input::handle(unsigned long len, unsigned long captured, 
			const unsigned char* f)
{

    int datalink = pcap_datalink(p);

    if (datalink == DLT_EN10MB) {

	// IPv4 ethernet only
	if (f[12] != 8) return;
	if (f[13] != 0) return;

	std::vector<unsigned char> v;
	v.assign(f + 14, f + len);

	// FIXME: Hard-coded?!
	std::string liid = "PCAP";

	try {
	    e.process(liid, v.begin(), v.end());
	} catch (std::exception& e) {
	    std::cerr << "Packet not processed: " << e.what() << std::endl;
	}
    }

}

int main(int argc, char** argv)
{
   
    if (argc != 3) {
	std::cerr << "Usage:" << std::endl
		  << "\tcybermon <port> <config>" << std::endl
		  << "or" << std::endl
		  << "\tcybermon - <config>" << std::endl;
	return 0;
    }
    
    try {

	// Get config file (Lua).
	std::string config = argv[2];
	
	// Create the observer instance.
	obs an(config);
	
	// Start the observer.
	an.start();

	std::string arg1(argv[1]);
	if (arg1 == "-") {

	    pcap_input pin("-", an);
	    pin.run();

	} else {
	
	    // Convert port argument to integer.
	    std::istringstream buf(argv[1]);
	    int port;
	    buf >> port;
	
	    // Create the monitor instance, receives ETSI events, and processes
	    // data.
	    etsi_monitor m(an);

	    // Start an ETSI receiver.
	    etsi_li::receiver r(port, m);
	    r.start();

	    // Wait forever.
	    r.join();

	}
	    
    } catch (std::exception& e) {
	
	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;
	
    }

}


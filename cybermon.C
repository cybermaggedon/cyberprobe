
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
    cybermon_lua cml;

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

    virtual void connection_data(const analyser::context_ptr cp,
				 analyser::pdu_iter s, analyser::pdu_iter e) {
	cml.connection_data(*this, cp, s, e);
    }

    // Connection-less
    virtual void datagram(const analyser::context_ptr cp,
			  analyser::pdu_iter s, analyser::pdu_iter e) {
	cml.datagram(*this, cp, s, e);
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
class cybermon : public monitor {
private:

    // Analysis engine
    analyser::engine& an;

public:

    // Short-hand for vector iterator.
    typedef std::vector<unsigned char>::iterator iter;

    // Constructor.
    cybermon(analyser::engine& an) : an(an) {}

    // Called when a PDU is received.
    virtual void operator()(const std::string& liid, const iter& s, 
			    const iter& e);

    // Called when attacker is discovered.
    void target_up(const std::string& liid, const tcpip::address& addr);

    // Called when attacker is disconnected.
    void target_down(const std::string& liid);
    
};

// Called when attacker is discovered.
void cybermon::target_up(const std::string& liid,
			 const tcpip::address& addr)
{
    an.target_up(liid, addr);
}

// Called when attacker is discovered.
void cybermon::target_down(const std::string& liid)
{
    an.target_down(liid);
}

// Called when a PDU is received.
void cybermon::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{

    // Get the root context.
//    analyser::context_ptr c = an.get_root_context(liid);

    try {

	// Process the PDU
//	an.process(c, s, e);
	an.process(liid, s, e);

    } catch (std::exception& e) {

	// Processing failure event.
	std::cerr << "Packet failed: " << e.what() << std::endl;

    }

}

int main(int argc, char** argv)
{
   
 if (argc != 3) {
	std::cerr << "Usage:" << "\tcybermon <port> <config>" << std::endl;
	return 0;
    }

  
    try {

	// Convert port argument to integer.
	std::istringstream buf(argv[1]);
	int port;
	buf >> port;
	
	// Get config file (Lua).
	std::string config = argv[2];
	
	// Create the observer instance.
	obs an(config);

	an.start();
	
	// Create the monitor instance, receives ETSI events, and processes
	// data.
	cybermon m(an);

	// Start an ETSI receiver.
	etsi_li::receiver r(port, m);
	r.start();

	// Wait forever.
	r.join();

    } catch (std::exception& e) {
	
	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;

    }

}


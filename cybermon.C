
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

#include "analyser.h"
#include "monitor.h"
#include "etsi_li.h"
#include "thread.h"
#include "packet_capture.h"
#include "flow.h"
#include "hexdump.h"
#include "context.h"

// My observation engine.  Uses the analyser engine, takes the data
// events and keep tabs on how much data has flowed out to attackers.
class obs : public analyser::engine {
public:

    // Map of network address to the amount of data acquired.
    std::map<analyser::address, uint64_t> amounts;

    // Stores the next 'reporting' event for data acquisition by an attacker.
    std::map<analyser::address, uint64_t> next;

    // Observation method.
    void data(const analyser::context_ptr f, const analyser::pdu_iter& s, 
	      const analyser::pdu_iter& e);

};

// Data method.  Keeps track of data flowing to an attacker and reports.
void obs::data(const analyser::context_ptr f, const analyser::pdu_iter& s, 
	       const analyser::pdu_iter& e)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    get_root_info(f, liid, trigger_address);

    // Get network addresses.
    analyser::address src, dest;
    get_network_info(f, src, dest);

    // Increment data counts flowing to the destination.
    amounts[dest] += (e - s);
    
    // Initialise an initial reporting event at 256k.
    if (next[dest] == 0)
	next[dest] = 256 * 1024;

    // If reached, report the event.
    if (amounts[dest] > next[dest]) {
	std::cerr << "Target " << liid << ": ";
	dest.describe(std::cout);
	std::cout  << " has received " 
		   << std::setprecision(2)
		   << std::fixed
		   << (float) amounts[dest] / 1024 / 1024 << "MB of data." 
		   << std::endl;

	// Double the reporting event value
	next[dest] = next[dest] * 2;

    }

    return;

}

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
    void discovered(const std::string& liid,
		    const tcpip::address& addr);

};

// Called when attacker is discovered.
void cybermon::discovered(const std::string& liid,
			  const tcpip::address& addr)
{

    // Get the root context for this LIID.
    analyser::context_ptr c = an.get_root_context(liid);

    // Record the known address.
    c->root().set_trigger_address(addr);

    // Report attacker.
    std::cerr << "Target " << liid << " discovered on IP " << addr
	      << std::endl;

}

// Called when a PDU is received.
void cybermon::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{

    // Get the root context.
    analyser::context_ptr c = an.get_root_context(liid);

    try {

	// Process the PDU
	an.process(c, s, e);

    } catch (std::exception& e) {

	// Processing failure event.
	std::cerr << "Packet failed: " << e.what() << std::endl;

    }

}

int main(int argc, char** argv)
{

    if (argc != 2) {
	std::cerr << "Usage:" << "\tcybermon <port>" << std::endl;
	return 0;
    }

    // Convert port argument to integer.
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    // Create the observer instance.
    obs an;

    // Create the monitor instance, receives ETSI events, and processes
    // data.
    cybermon m(an);

    // Start an ETSI receiver.
    etsi_li::receiver r(port, m);
    r.start();

    // Wait forever.
    r.join();

}


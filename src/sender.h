
#ifndef SENDER_H
#define SENDER_H

#include <queue>
#include <boost/shared_ptr.hpp>

#include "management.h"
#include <cybermon/thread.h>
#include <cybermon/nhis11.h>
#include <cybermon/etsi_li.h>
#include "parameters.h"

// Shared pointers to TCP/IP address.
typedef boost::shared_ptr<tcpip::address> address_ptr;

// A packet on the packet queue: LIID plus PDU.
class qpdu {
  public:
    enum { PDU, TARGET_UP, TARGET_DOWN } msg_type;
    std::string liid;		            // Valid for: PDU, TARGET_UP/DOWN
    std::vector<unsigned char> pdu;         // Valid for: PDU
    address_ptr addr;                       // Valid for: TARGET_UP
};

// Queue PDU pointer
typedef boost::shared_ptr<qpdu> qpdu_ptr;

// Sender base class.  Provides a queue input into a thread.
class sender : public threads::thread {
  protected:

    // Input queue: Lock, condition variable, max size and the actual
    // queue.
    threads::mutex lock;
    threads::condition cond;
    static const unsigned int max_packets = 1024;
    std::queue<qpdu_ptr> packets;

    // State: true if we're running, false if we've been asked to stop.
    bool running;

    parameters& global_pars;

  public:

    // Constructor.
    sender(parameters& p) : global_pars(p) {
	running = true;
    }

    // Thread body.
    virtual void run();

    // Handler - called to handle the next PDU on the queue.
    virtual void handle(qpdu_ptr) = 0;

    // Return information about the sender for the management interface.
    virtual void get_info(sender_info& info) = 0;

    // Destructor.
    virtual ~sender() {}

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

    // Hints about targets coming on/off-stream
    virtual void target_up(const std::string& l, const tcpip::address& a);
    virtual void target_down(const std::string& liid);

    // Called to push a packet down the sender transport.
    void deliver(const std::string& liid,
		 const_iterator& start,
		 const_iterator& end);

    // Called to stop the thread.
    virtual void stop() {
	running = false;
	cond.signal();
    }

};

// Implements an NHIS 1.1 sender plus input queue.  This manages the
// state of the NHIS 1.1 connection, re-connecting if required.
// This is a thread: You should create, called 'connect', call 'start' to
// spawn the thread, then call 'deliver' when you have packets to transmit.
class nhis11_sender : public sender {
  private:
  
    // NHIS 1.1 transport.
    std::map<std::string,cybermon::nhis11::sender> transport;

    // Connection details, host, port, transport.
    std::string h;
    unsigned short p;
    bool tls;

    // Params
    std::map<std::string, std::string> params;

  public:

    // Constructor.
    nhis11_sender(const std::string& h, unsigned short p,
		  const std::string& transp,
		  const std::map<std::string, std::string>& params,
		  parameters& globals) :
    sender(globals), h(h), p(p), params(params) {
	if (transp == "tls")
	    tls = true;
	else if (transp == "tcp")
	    tls = false;
	else
	    throw std::runtime_error("Transport " + transp + " not known.");
    }

    // Destructor.
    virtual ~nhis11_sender() {}

    // PDU handler
    virtual void handle(qpdu_ptr);

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

    // Return information about the sender for the management interface.
    virtual void get_info(sender_info& info) {
	info.hostname = h;
	info.port = p;
	info.type = "nhis1.1";
	
	std::ostringstream buf;
	buf << "NHIS 1.1 endpoint on " << h << ":" << p;
	info.description = buf.str();

    }

};

// Implements an ETSI LI sender plus input queue.  This manages the
// state of the LI connection, re-connecting if required.
// This is a thread: You should create, called 'connect', call 'start' to
// spawn the thread, then call 'deliver' when you have packets to transmit.
class etsi_li_sender : public sender {
  private:
  
    // ETSI LI transport and mux
    static const unsigned int num_connects = 4;
    unsigned int cur_connect = 0;
    cybermon::etsi_li::sender transports[num_connects];
    std::map<std::string,cybermon::etsi_li::sender&> transport_map;
    std::map<std::string,cybermon::etsi_li::mux> muxes;

    // Connection details, host, port, TLS.
    std::string h;
    unsigned short p;
    bool tls;			/* True if TLS enabled. */

    // Map, records if appropriate IRI BEGIN messages have been sent
    // to introduce this LIID.
    std::map<std::string, bool> setup;

    // Params
    std::map<std::string, std::string> params;

    // Initialise some configuration
    void initialise() { }

  public:

    // Constructor.
    etsi_li_sender(const std::string& h, unsigned int short p, 
                   const std::string& transp,
		   const std::map<std::string, std::string>& params,
		   parameters& globals) : 
    sender(globals), h(h), p(p), params(params)
    {
	if (transp == "tls")
	    tls = true;
	else if (transp == "tcp")
	    tls = false;
	else
	    throw std::runtime_error("Transport " + transp + " not known.");
	initialise(); 
    }

    // PDU handler
    virtual void handle(qpdu_ptr);

    // Destructor.
    virtual ~etsi_li_sender() {}

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

    // Return information about the sender for the management interface.
    virtual void get_info(sender_info& info) {
	info.hostname = h;
	info.port = p;
	info.type = "etsi";
	
	std::ostringstream buf;
	buf << "ETSI LI endpoint on " << h << ":" << p;
	info.description = buf.str();

    }

};

#endif



#ifndef SENDER_H
#define SENDER_H

#include <deque>

#include "thread.h"
#include "nhis11.h"
#include "etsi_li.h"
#include "parameters.h"

// A packet on the packet queue: LIID plus PDU.
class pdu {
  public:
    std::string liid;
    std::vector<unsigned char> pdu;
};

// Sender base class.  Provides a queue input into a thread.
class sender : public threads::thread {
  protected:

    // Input queue: Lock, condition variable, max size and the actual
    // queue.
    threads::mutex lock;
    threads::condition cond;
    static const int max_packets = 1024;
    std::deque<pdu> packets;

    // State: true if we're running, false if we've been asked to stop.
    bool running;

    parameters& pars;

  public:

    // Constructor.
    sender(parameters& p) : pars(p) {
	running = true;
    }

    // Destructor.
    virtual ~sender() {}

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

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
    std::map<std::string,nhis11::sender> transport;

    // Connection details, host, port and LIID.
    std::string h;
    unsigned short p;

  public:

    // Constructor.
    nhis11_sender(parameters& p) : sender(p) {}

    // Destructor.
    virtual ~nhis11_sender() {}

    // Doesn't actually connect, just defines the connection parameters.
    // Should be called before the 'deliver' method is called.
    void connect(const std::string& h, unsigned short p) {
	this->h = h; this->p = p;
    }

    // Thread method.
    virtual void run();

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

};

// Implements an ETSI LI sender plus input queue.  This manages the
// state of the LI connection, re-connecting if required.
// This is a thread: You should create, called 'connect', call 'start' to
// spawn the thread, then call 'deliver' when you have packets to transmit.
class etsi_li_sender : public sender {
  private:
  
    // ETSI LI transport and mux
    etsi_li::sender transport;
    etsi_li::mux mux;

    // Connection details, host, port and LIID.
    std::string h;
    unsigned short p;

    // Map, records if appropriate IRI BEGIN messages have been sent
    // to introduce this LIID.
    std::map<std::string, bool> setup;

    // Initialise some configuration
    void initialise() { }

  public:

    // Constructor.
    etsi_li_sender(parameters& p) : sender(p), mux(transport) { 
	initialise(); 
    }

    // Destructor.
    virtual ~etsi_li_sender() {}

    // Doesn't actually connect, just defines the connection parameters.
    // Should be called before the 'deliver' method is called.
    void connect(const std::string& h, unsigned short p) {
	this->h = h; this->p = p;
    }

    // Thread method.
    virtual void run();

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

};

#endif


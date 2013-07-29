//
// Packet capture stuff.  Wrapper around the PCAP library.
//
// To use this, sub-class the interface_capture class, and implement
// the 'handle' method which is called when a packet is received.

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <string>
#include <stdexcept>
#include <poll.h>
#include <vector>
#include <iostream>

extern "C" {
#include <pcap.h>
#include <pcap-bpf.h>
}

// Base class for capture functionality.  Use the 'interface_capture'
// class for interface sniffing.  This could be sub-classed to a PCAP
// file reader too, if needed.
class capture {

 protected:
    // PCAP handle.
    pcap_t* p;

 private:

    // Packet filter state.
    struct bpf_program fltr;

 protected:

    // Internal PCAP call-back.
    static void handler(unsigned char* usr, const struct pcap_pkthdr *h,
			const unsigned char* bytes) {
	class capture* c = (capture*) usr;
	c->handle(h->len, h->caplen, bytes);
    }

    bool running;

  public:
    
    // Constructor.
    capture() { p = 0; running = true; }

    // Destructor.
    virtual ~capture() { if (p) pcap_close(p); p = 0; }

    // Adds a filter to the capture class.  spec specifies a PCAP-style
    // filter statement.  See 'pcap' man-page.  Throws a runtime_error 
    // exception if compilation fails.
    void add_filter(const std::string& spec) {

	// Compile the expression.
	int ret = pcap_compile(p, &fltr, (char*) spec.c_str(), 1, 0);
	if (ret < 0)
	    throw std::runtime_error(pcap_geterr(p));

	// Attach to PCAP handle.
	ret = pcap_setfilter(p, &fltr);
	if (ret < 0) 
	    throw std::runtime_error(pcap_geterr(p));

    }

    // This is the method which gets called when a packet is received.
    // The user should implement this method.
    virtual void handle(unsigned long len, unsigned long captured, 
		const unsigned char* bytes) = 0;

    // Invokes packet processing on this capture handle, channelling received
    // packets through the 'handle' method.  Keeps processing forever or
    // until the 'stop' method is called.
    virtual void run() {

      struct pollfd pfd;
      pfd.fd = pcap_get_selectable_fd(p);
      pfd.events = POLLIN | POLLPRI;

      while (running) {

	  int ret = poll(&pfd, 1, 500);

	  if (pfd.revents)
	      pcap_dispatch(p, 1, handler, (unsigned char *) this);

      }


    }

    // Interrupts the 'run' method.
    void stop() {
	running = false;
    }

};

// Packet capture interface for a network interface.
class interface_capture : public capture {

  public:

    // Constructor.  'iface' is the interface name e.g. eth0
    // snaplen = maximum packet size to capture.
    interface_capture(const std::string& iface, int snaplen = 65535) {
	char errmsg[8192];
	p = pcap_open_live(iface.c_str(), snaplen, 1, 1, errmsg);
	if (p == 0)
	    throw std::runtime_error(errmsg);
    }
    

};

class pcap_writer {
  private:
    pcap_t* p;
    pcap_dumper_t* dumper;
  public:
    pcap_writer(const std::string& file = "-") {
	p = pcap_open_dead(DLT_RAW, 2000);
	if (p == 0)
	    throw std::runtime_error("pcap_open_dead failed.");
	dumper = pcap_dump_open(p, file.c_str());	
	if (dumper == 0)
	    throw std::runtime_error("pcap_dump_open_dead failed.");
    }
    void write(const std::vector<unsigned char>::iterator& begin,
	       const std::vector<unsigned char>::iterator& end) {

	struct pcap_pkthdr h;

	// Get time
	gettimeofday(&h.ts, 0);

	// Set packet lengths in header
	h.caplen = end - begin;
	h.len = end - begin;

	unsigned char buf[end - begin];
	std::copy(begin, end, buf);

	// Output in PCAP.
	pcap_dump((unsigned char *) dumper, &h, buf);

    }
    void close() {
	if (p == 0) return;
	pcap_dump_close(dumper);
	pcap_close(p);
    }
    ~pcap_writer() { close(); }
};

#endif


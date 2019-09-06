//
// Packet capture stuff.  Wrapper around the PCAP library.
//
// To use this, sub-class the interface_capture class, and implement
// the 'handle' method which is called when a packet is received.

#ifndef CYBERMON_PACKET_CAPTURE_H
#define CYBERMON_PACKET_CAPTURE_H

#include <string>
#include <stdexcept>
#include <poll.h>
#include <vector>
#include <iostream>
#include <string.h>
#include <sys/time.h>

extern "C" {
#include <pcap.h>
#include <pcap-bpf.h>
}

namespace cyberprobe {

namespace pcap {

class packet_handler {
public:
    virtual void handle(timeval tv, unsigned long len,
                        const unsigned char* bytes) = 0;
};

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
    packet_handler& handler;

protected:

    // Internal PCAP call-back.
    static void handle_packet(unsigned char* usr, const struct pcap_pkthdr *h,
                              const unsigned char* bytes)
        {
            capture* c = reinterpret_cast<capture*>(usr);
            c->handler.handle(h->ts, h->caplen, bytes);
        }

    bool running;

public:

    // Constructor.
    capture(packet_handler& h) : handler(h) {
        p = 0; running = true;
    }

    // Destructor.
    virtual ~capture() { if (p) pcap_close(p); p = 0; }

    // Adds a filter to the capture class.  spec specifies a PCAP-style
    // filter statement.  See 'pcap' man-page.  Throws a runtime_error
    // exception if compilation fails.
    void add_filter(const std::string& spec) {

	// Zero out the compilation filter.
        memset((void*) &fltr, 0, sizeof(fltr));

	// Compile the expression.
	int ret = pcap_compile(p, &fltr, (char*) spec.c_str(), 1, 0);
	if (ret < 0)
	    throw std::runtime_error(pcap_geterr(p));

	// Attach to PCAP handle.
	ret = pcap_setfilter(p, &fltr);
	if (ret < 0)
	    throw std::runtime_error(pcap_geterr(p));

    }

    // Invokes packet processing on this capture handle, channelling received
    // packets through the 'handle' method.  Keeps processing forever or
    // until the 'stop' method is called.
    virtual void run() {

        struct pollfd pfd;
        pfd.fd = pcap_get_selectable_fd(p);
        pfd.events = POLLIN | POLLPRI;

        while (running) {

            int ret = ::poll(&pfd, 1, 500);
            if (ret < 0)
                throw std::runtime_error("Poll failed");

            if (pfd.revents) {

                struct pcap_pkthdr* hdr;
                const unsigned char* data;

                int retval = pcap_next_ex(p, &hdr, &data);

                // Got a packet.
                if (retval == 1)
                    handle_packet((unsigned char*) this, hdr, data);

                // End of savefile.
                if (retval == -2)
                    break;

                // Error
                if (retval == -1)
                    throw std::runtime_error("PCAP failure");

            }

        }


    }

    // Interrupts the 'run' method.
    void stop() {
	running = false;
    }

};

// Packet capture interface for a network interface.
class interface : public capture {

public:

    // Constructor.  'iface' is the interface name e.g. eth0
    // snaplen = maximum packet size to capture.
    interface(packet_handler& h, const std::string& iface,
              int snaplen = 65535) : capture(h)
        {
            char errmsg[8192];
#ifdef HAVE_PCAP_CREATE
            p = pcap_create(iface.c_str(), errmsg);
            if (p == 0)
                throw std::runtime_error(errmsg);
            
            pcap_set_snaplen(p, 65535);
            if (pcap_can_set_rfmon(p))
                pcap_set_rfmon(p, 1);
            pcap_set_promisc(p, 1);
            
            int ret = pcap_activate(p);
            if (ret < 0) {
                throw std::runtime_error("pcap_activate failed");
            }
#else
            p = pcap_open_live(iface.c_str(), snaplen, 1, 1, errmsg);
            if (p == 0)
                throw std::runtime_error(errmsg);
#endif
        }

    virtual ~interface() {}

};

// File reader
class reader : public capture {

public:

    // Constructor.  'iface' is the interface name e.g. eth0
    // snaplen = maximum packet size to capture.
    reader(packet_handler& h, const std::string& path) : capture(h) {
	char errmsg[8192];
	p = pcap_open_offline(path.c_str(), errmsg);
	if (p == 0)
	    throw std::runtime_error(errmsg);
	pcap_set_snaplen(p, 65535);
    }

    virtual ~reader() {}


};

// Class, writes PCAP files.
class writer {
private:
    pcap_t* p;
    pcap_dumper_t* dumper;
public:
    writer(const std::string& file = "-") {
	p = pcap_open_dead(DLT_RAW, 65535);
	if (p == 0)
	    throw std::runtime_error("pcap_open_dead failed.");
	dumper = pcap_dump_open(p, file.c_str());
	if (dumper == 0)
	    throw std::runtime_error("pcap_dump_open_dead failed.");
    }

    void write(std::vector<unsigned char>::const_iterator begin,
	       std::vector<unsigned char>::const_iterator end) {

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
    ~writer() { close(); }
};

};

};

#endif


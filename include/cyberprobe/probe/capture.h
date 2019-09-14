
////////////////////////////////////////////////////////////////////////////
//
// PACKET CAPTURE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CAPTURE_H
#define CAPTURE_H

#include <cyberprobe/pkt_capture/packet_capture.h>
#include <cyberprobe/probe/packet_consumer.h>

#include <queue>
#include <thread>

namespace cyberprobe {

namespace capture {

class device {
public:
    virtual ~device() {}
    virtual void stop() = 0;
    virtual void start() = 0;
    virtual void join() = 0;

};

using packet_handler = cyberprobe::pcap::packet_handler;

class delayline : public device {
protected:

    // Handle to the deliver engine.
    packet_consumer& deliv;

    struct delayed_packet {
	std::vector<unsigned char> packet;
	struct timeval exit_time;
    };

    // Seconds of delay
    float delay;

    // PCAP's datalink enumerator - describes the type of layer 2 wrapping
    // on the IP packet.
    int datalink;

    // Delay converted to timeval form.
    struct timeval delay_val;

    std::queue<delayed_packet> delay_line;

public:

    delayline(packet_consumer& deliv, float delay, int datalink) :
        deliv(deliv), delay(delay), datalink(datalink) {

        // Calculate delay in form of a timeval.
        uint64_t delay_usec = delay * 1000000;
        delay_val.tv_usec = delay_usec % 1000000;
        delay_val.tv_sec = delay_usec / 1000000;

    }

    virtual ~delayline() {}
        
    // Packet handler.
    virtual void handle(timeval tv, unsigned long len,
			const unsigned char* bytes);

    virtual void service_delayline() {

	struct timeval now;
	gettimeofday(&now, 0);

	while (!(delay_line.empty())) {

	    if (delay_line.front().exit_time.tv_sec > now.tv_sec) break;

	    if ((delay_line.front().exit_time.tv_sec == now.tv_sec) &&
		(delay_line.front().exit_time.tv_usec > now.tv_usec))
		break;

	    // Packet ready to go.
	    deliv.receive_packet(now, delay_line.front().packet, datalink);
	    delay_line.pop();

	}

    }

};

class filtering_device : public delayline {

private:
    struct bpf_program fltr;
    pcap_t* p;
    bool filtering;

public:

    filtering_device(packet_consumer& deliv, float delay, int datalink) :
        delayline(deliv, delay, datalink) {

        // Only used for filtering.
        p = pcap_open_dead(datalink, 65535);
        if (p == 0) {
            std::cerr << "pcap_open_dead failed" << std::endl;
            return;
        }

        filtering = false;

    }

    virtual ~filtering_device() {

        if (filtering) {
            pcap_freecode(&fltr);
        }

        if (p) pcap_close(p);

    }

    virtual void add_filter(const std::string& spec) {

	// Compile the expression.
	int ret = pcap_compile(p, &fltr, (char*) spec.c_str(), 1, 0);

	if (ret < 0) {
	    std::cerr << "Filter expression compilation failed" << std::endl;
	    throw std::runtime_error(std::string("Filter expression failed: ") +
                                     pcap_geterr(p));
	    pcap_close(p);
	    return;

	}

	filtering = true;

    }

    template<class C>
    bool apply_filter(C s, C e) {

        // Construct PCAP header for filter
        struct pcap_pkthdr hdr;
        hdr.caplen = e - s;
        hdr.len = e - s;

        if (!filtering) return true;

        // Maybe apply filter
        if (pcap_offline_filter(&fltr, &hdr, &*s) != 0)
            return true;

        return false;

    }

};

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class interface : public cyberprobe::pcap::interface,
                  public packet_handler,
                  public delayline {
private:

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    interface(const std::string& i, float delay, packet_consumer& d) :
	cyberprobe::pcap::interface(*this, i),
        delayline(d, delay, pcap_datalink(p))
        {
            thr = 0;
        }

    // Destructor.
    virtual ~interface() {
	delete thr;
    }

    virtual void stop() {
        cyberprobe::pcap::interface::stop();
	running = false;
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&interface::run, this);
    }

     // Packet handler.
    virtual void handle(timeval tv, unsigned long len,
			const unsigned char* bytes) {
        delayline::handle(tv, len, bytes);
    }
    
};

};

};

#endif


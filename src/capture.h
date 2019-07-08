
////////////////////////////////////////////////////////////////////////////
//
// PACKET CAPTURE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CAPTURE_H
#define CAPTURE_H

#include <cybermon/packet_capture.h>
#include <packet_consumer.h>

#include <queue>
#include <thread>

class capture_dev {
public:
    virtual ~capture_dev() {}
    virtual void stop() = 0;
    virtual void start() = 0;
    virtual void join() = 0;
};

class delayline_dev : public capture_dev {
protected:

    // Handle to the deliver engine.
    packet_consumer& deliv;

    struct delayed_packet {
	std::vector<unsigned char> packet;
	struct timeval exit_time;
    };

    // PCAP's datalink enumerator - describes the type of layer 2 wrapping
    // on the IP packet.
    int datalink;

    // Seconds of delay
    float delay;

    // Delay converted to timeval form.
    struct timeval delay_val;

    std::queue<delayed_packet> delay_line;

public:

    delayline_dev(packet_consumer& deliv, int datalink) :
        deliv(deliv), datalink(datalink) {}

    virtual ~delayline_dev() {}
        
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

// Packet capture.  Captures on an interface, and then submits captured
// packets to the delivery engine.
class pcap_dev : public pcap_interface , public delayline_dev {
private:

    std::thread* thr;

public:

    // Thread body.
    virtual void run();

    // Constructor.  i=interface name, d=packet consumer.
    pcap_dev(const std::string& i, float delay, packet_consumer& d) :
	pcap_interface(i), delayline_dev(d, pcap_datalink(p)) {
	this->delay = delay;
	thr = 0;
    }

    // Destructor.
    virtual ~pcap_dev() {
	// FIXME: Wait for it to stop?
	delete thr;
    }

    virtual void stop() {
	pcap_interface::stop();
	running = false;
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&pcap_dev::run, this);
    }

     // Packet handler.
    virtual void handle(timeval tv, unsigned long len,
			const unsigned char* bytes) {
        delayline_dev::handle(tv, len, bytes);
    }
    
};

#endif


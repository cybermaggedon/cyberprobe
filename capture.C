
#include "capture.h"

// FIXME: Thread this for performance.

// Packet handler.
void capture_dev::handle(unsigned long len, unsigned long captured, 
		 const unsigned char* payload)
{

    if (delay == 0) {

	// Convert into a vector.
	std::vector<unsigned char> packet;
	packet.assign(payload, payload + captured);

	// Submit to the delivery engine.
	deliv.receive_packet(packet, datalink);

    } else {

	// Put a new packet on the delay line.
	delay_line.push(delayed_packet());

	// Set its exit time.
	gettimeofday(&(delay_line.back().exit_time), 0);
	delay_line.back().exit_time.tv_sec += delay;     // Add the delay.

	// Convert into a vector.
	std::vector<unsigned char> packet;
    
	// Put packet data on queue.
	delay_line.back().packet.assign(payload, payload + captured);

    }

}

// Capture device, main thread body.
void capture_dev::run()
{

    struct pollfd pfd;
    pfd.fd = pcap_get_selectable_fd(p);
    pfd.events = POLLIN | POLLPRI;
    
    while (running) {

	// Milli-second poll.
	int ret = poll(&pfd, 1, 1);
	if (ret < 0)
	    throw std::runtime_error("poll failed");

	if (pfd.revents)
	    pcap_dispatch(p, 1, handler, (unsigned char *) this);

	struct timeval now;
	gettimeofday(&now, 0);

	while (!(delay_line.empty())) {

	    if (delay_line.front().exit_time.tv_sec > now.tv_sec) break;

	    if ((delay_line.front().exit_time.tv_sec == now.tv_sec) &&
		(delay_line.front().exit_time.tv_usec > now.tv_usec))
		break;

	    // Packet ready to go.
	    deliv.receive_packet(delay_line.front().packet, datalink);
	    delay_line.pop();


	}

    }

}


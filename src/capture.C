
#include "capture.h"
#include <stdint.h>
#include <unistd.h>

// FIXME: Thread this for performance.

// Packet handler.
void pcap_dev::handle(timeval tv, unsigned long len, unsigned long captured,
		      const unsigned char* payload)
{

    // Bypass the delay line stuff if there's no delay.
    if (delay == 0.0) {

	// Convert into a vector.
	std::vector<unsigned char> packet;
	packet.assign(payload, payload + captured);

	// Submit to the delivery engine.
	deliv.receive_packet(tv, packet, datalink);

    } else {

	// Put a new packet on the delay line.
	delay_line.push(delayed_packet());

	// Get time now.
	struct timeval now;
	gettimeofday(&now, 0);

	// Set packet exit time.
	timeradd(&now, &delay_val, &(delay_line.back().exit_time));

	// Put packet data on queue.
	delay_line.back().packet.assign(payload, payload + captured);

    }

}

// Capture device, main thread body.
void pcap_dev::run()
{

    struct pollfd pfd;
    pfd.fd = pcap_get_selectable_fd(p);
    pfd.events = POLLIN | POLLPRI;

    // Calculate delay in form of a timeval.
    uint64_t delay_usec = delay * 1000000;
    delay_val.tv_usec = delay_usec % 1000000;
    delay_val.tv_sec = delay_usec / 1000000;

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
            // Time of packets from delay line will be 'now'
	    deliv.receive_packet((struct timeval){0}, delay_line.front().packet, datalink);
	    delay_line.pop();


	}

    }

}


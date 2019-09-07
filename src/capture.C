
#include <cyberprobe/probe/capture.h>

#include <stdint.h>
#include <unistd.h>

// FIXME: Thread this for performance.
using namespace cyberprobe::capture;

// Packet handler.
void delayline::handle(timeval tv, unsigned long len,
                       const unsigned char* payload)
{

    // Bypass the delay line stuff if there's no delay.
    if (delay == 0.0) {

	// Convert into a vector.
	std::vector<unsigned char> packet;
	packet.assign(payload, payload + len);

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
	delay_line.back().packet.assign(payload, payload + len);

    }

}

// Capture device, main thread body.
void interface::run()
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
            pcap_dispatch(p, 1, handle_packet, (unsigned char *) this);

        service_delayline();

    }

}


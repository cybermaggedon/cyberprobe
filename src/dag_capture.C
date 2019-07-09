
#include "dag_capture.h"
#include "capture.h"
#include <stdint.h>
#include <unistd.h>
#include <dagapi.h>
#include <arpa/inet.h>

// Capture device, main thread body.
void dag_dev::run()
{

    // This is a thread. No point throwing exceptions.

    uint64_t window = 16 * 1024 * 1024;

    std::string dev_file = "/dev/" + iface;

    int fd = dag_open((char*) dev_file.c_str());
    if (fd < 0) {
	std::cerr << "dag_open failed: " << errno << std::endl;
	perror("dag_open");
	return;
    }

    int ret = dag_attach_stream64(fd, 0, 0, window);
    if (ret < 0) {
	std::cerr << "dag_attach_stream failed." << std::endl;
	perror("dag_attach_stream64");
	return;
    }

    ret = dag_start_stream(fd, 0);
    if (ret < 0) {
        std::cerr << "dag_start_stream failed." << std::endl;
        perror("dag_start_stream");
        exit(0);
    }

    // 50ms max wait
    struct timeval maxwait;
    timerclear(&maxwait);
    maxwait.tv_sec = 50000;

    // 1ms timeout when data present - keeps latency low
    struct timeval poll;
    timerclear(&poll);
    poll.tv_usec = 1000;

    // Wait for 1024 bytes or poll timeout.
    dag_set_stream_poll64(fd, 0, 1024, &maxwait, &poll);

    uint8_t* top = 0;
    uint8_t* bottom = 0;

    while (running) {

	top = dag_advance_stream(fd, 0, &bottom);
	if (top == 0) {
	    if (errno == EAGAIN) continue;
	    perror("dag_advance_stream");
	    return;
	}

	int diff = top - bottom;

	if (diff == 0) {
	    continue;
	}

	uint64_t processed = 0;

	while (running && ((top - bottom) > dag_record_size) &&
	       ((processed + dag_record_size) < window)) {

	    dag_record_t* rec = (dag_record_t*) bottom;

	    uint64_t len = ntohs(rec->rlen);

	    if ((top - bottom) < len)
		break;

	    int type = rec->type & 0x7f;

	    int pos = 0;

	    // Skip timestamp
	    pos += 8;

	    // Skip over 8-bytes and all extension headers.
	    while (bottom[pos] & 0x80)
		pos += 8;
	    pos += 8;

	    // Type-specific.
	    if (type == 1) pos += 4;
	    if (type == 2) pos += 2;
	    if (type == 3) pos += 4;
	    if (type == 16) pos += 2;

            if (apply_filter(bottom + pos, bottom + len)) {

		// No filter in place, or filter hits.
                timeval tv = {0};
		handle(tv, len - pos, bottom + pos);

	    }

	    processed += len;
	    bottom += len;

	}

	// Maybe clear some delay line.
	// FIXME: Copied from capture.C

        service_delayline();

    }

    dag_stop_stream(fd, 0);
    dag_detach_stream(fd, 0);

    dag_close(fd);

}



#include "dag_capture.h"
#include "capture.h"
#include <stdint.h>
#include <unistd.h>
#include <dagapi.h>
#include <arpa/inet.h>

// Packet handler.
void dag_dev::handle(unsigned long len, unsigned long captured, 
		     const unsigned char* payload)
{

    // FIXME: Copied from capture.C

    // Bypass the delay line stuff if there's no delay.
    if (delay == 0.0) {

	// Convert into a vector.
	std::vector<unsigned char> packet;
	packet.assign(payload, payload + captured);

	// Submit to the delivery engine.
	deliv.receive_packet(packet, datalink);

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
void dag_dev::run()
{

    // This is a thread. No point throwing exceptions.
    
    uint64_t window = 16 * 1024 * 1024;

    struct bpf_program fltr;

    // Only used for filtering.
    pcap_t *p = pcap_open_dead(datalink, 65535);
    if (p == 0) {
	std::cerr << "pcap_open_dead failed" << std::endl;
	return;
    }
    
    bool apply_filter = false;

    if (filter != "") {

	// Compile the expression.
	int ret = pcap_compile(p, &fltr, (char*) filter.c_str(), 1, 0);
	if (ret < 0) {

	    std::cerr << "Filter expression compilation failed" << std::endl;
	    std::cerr << pcap_geterr(p) << std::endl;
	    pcap_close(p);
	    return;

	}

	apply_filter = true;

    }

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

	    // Construct PCAP header for filter
	    struct pcap_pkthdr hdr;
	    hdr.caplen = len - pos;
	    hdr.len = len - pos;

	    // Maybe apply filter
	    if (apply_filter == false ||
		pcap_offline_filter(&fltr, &hdr, bottom + pos) != 0) {

		// No filter in place, or filter hits.
		handle(len - pos, len - pos, bottom + pos);

	    }

	    processed += len;
	    bottom += len;
      
	}

	// Maybe clear some delay line.
	// FIXME: Copied from capture.C

	// Get time
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

    if (filter != "") {
	pcap_freecode(&fltr);
    }

    if (p) pcap_close(p);
    
    dag_stop_stream(fd, 0);
    dag_detach_stream(fd, 0);
    
    dag_close(fd);

}


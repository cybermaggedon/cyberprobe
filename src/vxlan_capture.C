
#include <vxlan_capture.h>

#include <cybermon/socket.h>

#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

// Capture device, main thread body.
void vxlan_capture::run()
{

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

    // Start UDP service
    tcpip::udp_socket recv;
    recv.bind(port);

    while (running) {

        // Rattling around this loop allows clearing the delay line.
        bool activ = recv.poll(0.05);

        if (activ) {

            std::vector<unsigned char> buffer;
            
            recv.read(buffer, 65536);

            // Ignore truncated VXLAN.
            if (buffer.size() < 8) continue;

            // VXLAN header (8-bytes):
            //   Flags: 8-bits, bit 3 = VNI is valid.
            //   Reserved: 24 bits
            //   VNI: 24 bits
            //   Reserved: 8 bits
            
            uint32_t vxlan_id = 0;

            unsigned int vlan_id;

            // Start from the end of VXLAN header.
            std::vector<unsigned char>::const_iterator s = buffer.begin() + 8;
            std::vector<unsigned char>::const_iterator e = buffer.end();

	    // Construct PCAP header for filter
	    struct pcap_pkthdr hdr;
	    hdr.caplen = e - s;
	    hdr.len = e - s;

	    // Maybe apply filter
	    if (apply_filter == false ||
		pcap_offline_filter(&fltr, &hdr, &*s) != 0) {

		// No filter in place, or filter hits.
                timeval tv = {0};

		handle(tv, e - s, &s[0]);

	    }

	}

	// Maybe clear some delay line.
        service_delayline();

    }

    if (filter != "") {
	pcap_freecode(&fltr);
    }

    if (p) pcap_close(p);

}


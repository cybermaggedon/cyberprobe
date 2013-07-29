
#include <iostream>
#include <sys/types.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string>
#include <arpa/inet.h>
#include "socket.h"

const int alert_message_len = 256;
const int capture_len = 1500;
const std::string socket_file = "snort_alert";

struct snort_event {
    uint32_t sig_generator;
    uint32_t sig_id;
    uint32_t sig_rev;
    uint32_t classification;
    uint32_t priority;
    uint32_t event_id;
    uint32_t event_ref;
    struct timeval ref_time;
};

struct snort_alert {
    unsigned char message[alert_message_len];
    pcap_pkthdr pcaphdr;
    uint32_t dlt_hdr;
    uint32_t net_hdr;
    uint32_t trans_hdr;
    uint32_t data;
    uint32_t flags;
    unsigned char packet[1500];
};

int main(int argc, char** argv)
{


    tcpip::unix_socket sock;

    sock.bind(socket_file);

    while (1) {

	snort_alert alert;

	int recvd = sock.read(reinterpret_cast<char*>(&alert), sizeof(alert));
	
	if (recvd == 0) break;
	if (recvd < 0) {
	    perror("recv"); exit(1);
	}

	if (recvd != sizeof(alert)) continue;

	std::cout << "Alert!" << std::endl;

	if (alert.flags & 1) continue;

	unsigned char* ip_hdr = alert.packet + alert.net_hdr;

	struct tcpip::ip4_address src;

	src.addr.assign(ip_hdr + 12, ip_hdr + 16);


	std::cout << "Src addr = " << src
		  << std::endl;

    }

}


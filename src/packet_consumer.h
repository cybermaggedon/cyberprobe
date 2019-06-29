
#ifndef PACKET_CONSUMER_H
#define PACKET_CONSUMER_H

#include <sys/time.h>

class packet_consumer {
public:
    virtual ~packet_consumer() {}

    // Allows caller to provide an IP packet for delivery.
    virtual void receive_packet(timeval tv, const std::vector<unsigned char>& packet,
				int datalink) = 0;

};

#endif


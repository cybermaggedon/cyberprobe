
#ifndef PACKET_CONSUMER_H
#define PACKET_CONSUMER_H

class packet_consumer {
  public:
    virtual ~packet_consumer() {}

    // Allows caller to provide an IP packet for delivery.
    virtual void receive_packet(const std::vector<unsigned char>& packet, 
				int datalink) = 0;

};

#endif


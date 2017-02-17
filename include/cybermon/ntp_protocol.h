
#ifndef CYBERMON_NTP_PROTOCOL_H
#define CYBERMON_NTP_PROTOCOL_H

#include <stdint.h>

#include <string>

#include <cybermon/pdu.h>
#include <cybermon/address.h>

namespace cybermon
{

struct ntp_base
{
    unsigned int leap_indicator;
    unsigned int version;
    unsigned int mode;
};


struct ntp_timestamp : public ntp_base
{
    unsigned int stratum;
    double poll;
    double precision;   
    double root_delay;
    double root_dispersion;
    unsigned int reference_id;
    double reference_timestamp;
    double originate_timestamp;
    double receive_timestamp;
    double transmit_timestamp;
    bool has_extension;
};

struct ntp_control : public ntp_base
{
};

struct ntp_private : public ntp_base
{
};


class ntp_decoder
{
public:

    ntp_decoder(pdu_iter s, pdu_iter e);

    enum packet_type
    {
        timestamp_packet,
        control_packet,
        private_packet,
        unknown_packet
    };
    
    packet_type parse();
    ntp_timestamp timestamp_info;
    ntp_control control_info;
    ntp_private private_info;

private:
    pdu_iter start;
	pdu_iter end;
	pdu_iter ptr;
	
	packet_type parse_timestamp();
	packet_type parse_control();
	packet_type parse_private();
	void parse_base(ntp_base& base);
	unsigned int get_uint32();
	double log2decimal();
	double ntp_short();
	double ntp_ts();
};

}

#endif

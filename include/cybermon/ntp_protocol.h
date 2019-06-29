
#ifndef CYBERMON_NTP_PROTOCOL_H
#define CYBERMON_NTP_PROTOCOL_H

#include <stdint.h>

#include <string>

#include <cybermon/pdu.h>
#include <cybermon/address.h>

namespace cybermon
{

    struct ntp_hdr
    {
        unsigned int m_leap_indicator;
        unsigned int m_version;
        unsigned int m_mode;
    };

    struct ntp_timestamp
    {
        ntp_hdr m_hdr;
        unsigned int m_stratum;
        double m_poll;
        double m_precision;   
        double m_root_delay;
        double m_root_dispersion;
        unsigned int m_reference_id;
        double m_reference_timestamp;
        double m_originate_timestamp;
        double m_receive_timestamp;
        double m_transmit_timestamp;
        bool m_has_extension;
    };

    struct ntp_control
    {
        ntp_hdr m_hdr;
        bool m_is_response;
        bool m_is_error;
        bool m_is_fragment;
        unsigned int m_opcode;
        unsigned int  m_sequence;
        unsigned int  m_status;
        unsigned int  m_association_id;
        unsigned int  m_offset;
        unsigned int  m_data_count;
        bool m_has_authentication;
    };

    struct ntp_private
    {
        ntp_hdr m_hdr;
        bool m_auth_flag;
        unsigned int m_sequence;
        unsigned int m_implementation;
        unsigned int m_request_code;
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
        const ntp_timestamp& get_timestamp_info() const;
        const ntp_control& get_control_info() const;
        const ntp_private& get_private_info() const;
    
    private:
        pdu_iter m_start;
	pdu_iter m_end;
	pdu_iter m_ptr;
	ntp_timestamp m_timestamp;
        ntp_control m_control;
        ntp_private m_private;
	
	packet_type parse_timestamp();
	packet_type parse_control();
	packet_type parse_private();
	void parse_hdr(ntp_hdr& hdr);
	size_t remaining();
	uint16_t get_uint16();
	unsigned int get_uint32();
	double log2decimal();
	double ntp_short();
	double ntp_ts();
    };

}

#endif

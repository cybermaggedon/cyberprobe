#include <cyberprobe/protocol/ntp_protocol.h>

#include <math.h>
#include <string>
#include <vector>

using namespace cyberprobe::protocol;

ntp_decoder::ntp_decoder(pdu_iter s, pdu_iter e)
    : m_start(s), m_end(e), m_ptr(s)
{
}
	
ntp_decoder::packet_type ntp_decoder::parse()
{
    packet_type pt = unknown_packet;
    
    const uint8_t mode = m_ptr[0] & 0x07;
   
    switch(mode)
        {
        case 0x06:
            pt = parse_control();
            break;
        case 0x07:
            pt =  parse_private();
            break;
        default:
            pt = parse_timestamp();
            break;
        }
    
    return pt;
}

const ntp_timestamp& ntp_decoder::get_timestamp_info() const
{
    return m_timestamp;
}

const ntp_control& ntp_decoder::get_control_info() const
{
    return m_control;
}

const ntp_private& ntp_decoder::get_private_info() const
{
    return m_private;
}

ntp_decoder::packet_type ntp_decoder::parse_timestamp()
{
    // need at least 48 bytes
    const size_t min_timestamp_length = 48;
    if (remaining() < min_timestamp_length)
        {
            return unknown_packet;
        }
    
    parse_hdr(m_timestamp.m_hdr);
    m_timestamp.m_stratum = *m_ptr++;
    m_timestamp.m_poll = log2decimal();
    m_timestamp.m_precision = log2decimal();
    m_timestamp.m_root_delay = ntp_short();
    m_timestamp.m_root_dispersion = ntp_short();
    m_timestamp.m_reference_id = get_uint32();
    m_timestamp.m_reference_timestamp = ntp_ts();
    m_timestamp.m_originate_timestamp = ntp_ts();
    m_timestamp.m_receive_timestamp = ntp_ts();
    m_timestamp.m_transmit_timestamp = ntp_ts();
    m_timestamp.m_has_extension = remaining();
    
    return timestamp_packet;
}

ntp_decoder::packet_type ntp_decoder::parse_control()
{
    const size_t min_ctrl_length = 12;
    if (remaining() < min_ctrl_length)
        {
            return unknown_packet;
        }
    
    parse_hdr(m_control.m_hdr);
    
    m_control.m_is_response = m_ptr[0] & 0x80;
    m_control.m_is_error = m_ptr[0] & 0x40;
    m_control.m_is_fragment = m_ptr[0] & 0x20;
    m_control.m_opcode = m_ptr[0] & 0x1F;
    m_ptr++;
    
    m_control.m_sequence = get_uint16();
    m_control.m_status = get_uint16();
    m_control.m_association_id = get_uint16();
    m_control.m_offset = get_uint16();
    m_control.m_data_count = get_uint16();
    
    const size_t max_data_length = 468;
    if(m_control.m_data_count > max_data_length ||
       remaining() < m_control.m_data_count)
        {
            return unknown_packet;
        }
    m_ptr += m_control.m_data_count;
    m_control.m_has_authentication = remaining();
   
    return control_packet;
}

ntp_decoder::packet_type ntp_decoder::parse_private()
{
    const size_t min_priv_length = 5;
    if (remaining() < min_priv_length)
        {
            return unknown_packet;
        }
    
    parse_hdr(m_private.m_hdr);
    m_private.m_auth_flag = m_ptr[0] & 0x80;
    m_private.m_sequence = *m_ptr++;
    m_private.m_implementation = *m_ptr++;
    m_private.m_request_code = *m_ptr++;
    
    return private_packet;
}

void ntp_decoder::parse_hdr(ntp_hdr& hdr)
{
    hdr.m_leap_indicator = (m_ptr[0] & 0xC0) >> 6;
    hdr.m_version = (m_ptr[0] & 0x38) >> 3;
    hdr.m_mode = m_ptr[0] & 0x07;
    m_ptr++;
}

size_t ntp_decoder::remaining()
{
    return m_end - m_ptr;
}

uint16_t ntp_decoder::get_uint16()
{
    const uint16_t val = (m_ptr[0] << 16) | m_ptr[1];
    m_ptr += 2;
    return val;
}

unsigned int ntp_decoder::get_uint32()
{
    const unsigned int val = (m_ptr[0] << 24) | (m_ptr[1] << 16) | (m_ptr[2] << 8) | m_ptr[3];
    m_ptr += 4;
    return val;
}

double ntp_decoder::log2decimal()
{
    const char val = *m_ptr++;
    return ((val) < 0 ? 1. / (1L << -(val)) : 1L << (val));
}

double ntp_decoder::ntp_short()
{
    const long units = 0x10000;
    return ((double)(get_uint32()) / units);
}

double ntp_decoder::ntp_ts()
{
    double ntp_time = 0.0;

    unsigned int secs = get_uint32();
    if(secs)
        {
            // this calculation must me done using unsigned types
            // to get dates > 2038 to work according to RFC2030
            const unsigned int ntp_base_time = 2208988800;
            secs -= ntp_base_time;
            ntp_time = (double)secs;
        }

    unsigned int nsecs = get_uint32();
    if(nsecs)
        {
            const long units = 0x100000000;
            ntp_time += ((double)(nsecs) / units);
        }
    
    return ntp_time;
}







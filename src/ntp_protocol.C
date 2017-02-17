#include <cybermon/ntp_protocol.h>

#include <math.h>
#include <string>
#include <vector>

namespace
{	
	#define NTP_LI_MASK	0xC0
	#define NTP_VN_MASK	0x38
    
    #define NTP_MODE_MASK   0x7
    #define NTP_MODE_CTRL	0x6
    #define NTP_MODE_PRIV	0x7
	
	#define NTP_BASETIME 2208988800u
}


using namespace cybermon;


ntp_decoder::ntp_decoder(pdu_iter s, pdu_iter e)
  : start(s), end(e), ptr(s)
{
}
	

ntp_decoder::packet_type ntp_decoder::parse()
{
    packet_type pt = unknown_packet;
    
    uint8_t mode = ptr[0] & NTP_MODE_MASK;
   
    switch(mode)
    {
        case NTP_MODE_CTRL:
            pt = parse_control();
            break;
        case NTP_MODE_PRIV:
            pt =  parse_private();
            break;
        default:
            pt = parse_timestamp();
            break;
    }
    
    return pt;
}

ntp_decoder::packet_type ntp_decoder::parse_timestamp()
{
    // need at least 48 bytes
    if ((end - start) < 48)
    {
        return unknown_packet;
    }
    
    parse_base(timestamp_info);
    timestamp_info.stratum = *ptr++;
    timestamp_info.poll = log2decimal();
    timestamp_info.precision = log2decimal();
    
    timestamp_info.root_delay = ntp_short();
    timestamp_info.root_dispersion = ntp_short();
    
    /*timestamp_info.root_delay = ( ((ptr[0] << 8) | ptr[1]) +
                                  (((ptr[2] << 8) | ptr[3]) / 65536.0) );
    ptr += 4;
    timestamp_info.root_dispersion = ( ((ptr[0] << 8) | ptr[1]) +
                                       (((ptr[2] << 8) | ptr[3]) / 65536.0) );
    ptr += 4;*/
    
    timestamp_info.reference_id = get_uint32();
    timestamp_info.reference_timestamp = ntp_ts();
    timestamp_info.originate_timestamp = ntp_ts();
    timestamp_info.receive_timestamp = ntp_ts();
    timestamp_info.transmit_timestamp = ntp_ts();
    
    timestamp_info.has_extension = (end == ptr) ? true : false;
    
    return timestamp_packet;
}

ntp_decoder::packet_type ntp_decoder::parse_control()
{
    if ((end - start) < 1)
    {
        return unknown_packet;
    }
    
    parse_base(control_info);
    
    return control_packet;
}

ntp_decoder::packet_type ntp_decoder::parse_private()
{
    if ((end - start) < 1)
    {
        return unknown_packet;
    }
    
    parse_base(private_info);
    
    return private_packet;
}

void ntp_decoder::parse_base(ntp_base& base)
{
    timestamp_info.leap_indicator = (ptr[0] & NTP_LI_MASK) >> 6;
    timestamp_info.version = (ptr[0] & NTP_VN_MASK) >> 3;
    timestamp_info.mode= ptr[0] & NTP_MODE_MASK;
    ptr++;
}

unsigned int ntp_decoder::get_uint32()
{
    unsigned int val = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
    ptr += 4;
    return val;
}

double ntp_decoder::log2decimal()
{
    char val = *ptr++;
    return ((val) < 0 ? 1. / (1L << -(val)) : 1L << (val));
}

double ntp_decoder::ntp_short()
{
    return ((double)(get_uint32()) / 0x10000L);
}

double ntp_decoder::ntp_ts()
{
    double ntp_time = 0.0;

    unsigned int secs = get_uint32();
    if(secs)
    {
        // this calculation must me done using unsigned types
        // to get dates > 2038 to work according to RFC2030
        secs -= NTP_BASETIME;
        ntp_time = (double)secs;
    }

    unsigned int nsecs = get_uint32();
    if(nsecs)
    {
        ntp_time += ((double)(nsecs) / 0x100000000L);
    }
    
    return ntp_time;
}






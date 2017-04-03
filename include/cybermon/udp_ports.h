////////////////////////////////////////////////////////////////////////////
//
// UDP Ports
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_UDP_PORTS_H
#define CYBERMON_UDP_PORTS_H


#include <cybermon/context.h>
#include <cybermon/dns_over_udp.h>
#include <cybermon/manager.h>
#include <cybermon/ntp.h>
#include <cybermon/pdu.h>
#include <cybermon/rtp.h>
#include <cybermon/rtp_ssl.h>
#include <cybermon/sip.h>
#include <cybermon/sip_ssl.h>


namespace cybermon
{

typedef void (*fn)(manager& mgr, context_ptr fc, pdu_iter s, pdu_iter e);

static fn udp_port_handlers[65535] = {};


static bool udp_handlers_initialised = false;


static void init_udp_handlers(void)
{
    // Initialize all elements to null first
    for(uint16_t x = 0; x < 65535; x++)
    {
        udp_port_handlers[x] = NULL;
    }

    // Now assign specific handlers
    udp_port_handlers[53]  = &dns_over_udp::process;
    udp_port_handlers[123] = &ntp::process;
    udp_port_handlers[5004] = &rtp::process;
    udp_port_handlers[5005] = &rtp_ssl::process;
    udp_port_handlers[5060] = &sip::process;
    udp_port_handlers[5061] = &sip_ssl::process;

    // Set flag to true to avoid the above
    // being repeatedly called in the future
    udp_handlers_initialised = true;
}


static bool is_udp_handlers_init(void)
{
    return udp_handlers_initialised;
}


}; // End namespace

#endif

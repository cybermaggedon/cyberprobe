
#include <cybermon/udp_ports.h>

#include <cybermon/dns_over_udp.h>
#include <cybermon/ntp.h>
#include <cybermon/rtp.h>
#include <cybermon/rtp_ssl.h>
#include <cybermon/sip.h>
#include <cybermon/sip_ssl.h>


using namespace cybermon;


udp_ports::fn udp_ports::port_handler[65535] = {};

bool udp_ports::handlers_initialised = false;


void udp_ports::init_handlers(void)
{
    // Initialize all elements to null first
    for(uint16_t x = 0; x < 65535; x++)
    {
        port_handler[x] = NULL;
    }

    // Now assign specific handlers
    port_handler[53]  = &dns_over_udp::process;
    port_handler[123] = &ntp::process;
    port_handler[5060] = &sip::process;
    port_handler[5061] = &sip_ssl::process;

    // Set flag to true to avoid the above
    // being repeatedly called in the future
    handlers_initialised = true;
}


bool udp_ports::is_handlers_init(void)
{
    return handlers_initialised;
}

void udp_ports::add_port_handler(uint16_t port, fn function)
{
    if (port_handler[port] == NULL)
    {
        port_handler[port] = function;
    }
    else
    {
// Temporarily comment out until ports can be removed
//        throw exception("Handler already assigned to UDP port");
    }
}

void udp_ports::remove_port_handler(uint16_t port)
{
    port_handler[port] = NULL;
}

bool udp_ports::has_port_handler(uint16_t port)
{
    if (port_handler[port] != NULL)
    {
        return true;
    }

    return false;
}

udp_ports::fn udp_ports::get_port_handler(uint16_t port)
{
    return port_handler[port];
}


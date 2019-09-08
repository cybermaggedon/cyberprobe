
#include <cyberprobe/protocol/udp_ports.h>

#include <cyberprobe/protocol/dns_over_udp.h>
#include <cyberprobe/protocol/ntp.h>
#include <cyberprobe/protocol/rtp.h>
#include <cyberprobe/protocol/rtp_ssl.h>
#include <cyberprobe/protocol/sip.h>
#include <cyberprobe/protocol/sip_ssl.h>


using namespace cyberprobe::protocol;


std::vector<udp_ports::fn> udp_ports::port_handler(65536, nullptr);

bool udp_ports::handlers_initialised = false;


void udp_ports::init_handlers(void)
{

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
    if (port_handler[port] == nullptr)
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
    port_handler[port] = nullptr;
}

bool udp_ports::has_port_handler(uint16_t port)
{
    if (port_handler[port] != nullptr)
        {
            return true;
        }

    return false;
}

udp_ports::fn udp_ports::get_port_handler(uint16_t port)
{
    return port_handler[port];
}


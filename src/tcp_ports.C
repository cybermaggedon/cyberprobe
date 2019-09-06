#include <cyberprobe/protocol/tcp_ports.h>

#include <cyberprobe/protocol/dns_over_tcp.h>
#include <cyberprobe/protocol/ftp.h>
#include <cyberprobe/protocol/imap.h>
#include <cyberprobe/protocol/imap_ssl.h>
#include <cyberprobe/protocol/pop3.h>
#include <cyberprobe/protocol/pop3_ssl.h>
#include <cyberprobe/protocol/rtp.h>
#include <cyberprobe/protocol/rtp_ssl.h>
#include <cyberprobe/protocol/sip.h>
#include <cyberprobe/protocol/sip_ssl.h>
#include <cyberprobe/protocol/smtp.h>
#include <cyberprobe/protocol/smtp_auth.h>
#include <cyberprobe/protocol/tls.h>


using namespace cyberprobe::protocol;


std::vector<tcp_ports::fn> tcp_ports::port_handler(65536, nullptr);

bool tcp_ports::handlers_initialised = false;


void tcp_ports::init_handlers(void)
{

    // Now assign specific handlers
    port_handler[21]  = &ftp::process;
    port_handler[25]  = &smtp::process;
    // DNS over TCP is broken if packets span multiple TCP PDUs.
    //    port_handler[53]  = &dns_over_tcp::process;
    port_handler[110] = &pop3::process;
    port_handler[220] = &imap::process;
    port_handler[443] = &tls::process;
    port_handler[465] = &smtp_auth::process;
    port_handler[993] = &imap_ssl::process;
    port_handler[995] = &pop3_ssl::process;
    port_handler[5060] = &sip::process;
    port_handler[5061] = &sip_ssl::process;


    // Set flag to true to avoid the above
    // being repeatedly called in the future
    handlers_initialised = true;
}


bool tcp_ports::is_handlers_init(void)
{
    return handlers_initialised;
}


void tcp_ports::add_port_handler(uint16_t port, fn function)
{
    if (port_handler[port] == NULL)
        {
            port_handler[port] = function;
        }
    else
        {
// Temporarily comment out until ports can be removed
//        throw exception("Handler already assigned to TCP port");
        }
}

void tcp_ports::remove_port_handler(uint16_t port)
{
    port_handler[port] = NULL;
}

bool tcp_ports::has_port_handler(uint16_t port)
{
    if (port_handler[port] != nullptr)
        {
            return true;
        }

    return false;
}

tcp_ports::fn tcp_ports::get_port_handler(uint16_t port)
{
    return port_handler[port];
}


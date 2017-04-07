////////////////////////////////////////////////////////////////////////////
//
// TCP Ports
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_TCP_PORTS_H
#define CYBERMON_TCP_PORTS_H


#include <cybermon/context.h>
#include <cybermon/dns_over_tcp.h>
#include <cybermon/ftp.h>
#include <cybermon/imap.h>
#include <cybermon/imap_ssl.h>
#include <cybermon/manager.h>
#include <cybermon/pop3.h>
#include <cybermon/pop3_ssl.h>
#include <cybermon/pdu.h>
#include <cybermon/rtp.h>
#include <cybermon/rtp_ssl.h>
#include <cybermon/sip.h>
#include <cybermon/sip_ssl.h>
#include <cybermon/smtp.h>
#include <cybermon/smtp_auth.h>


namespace cybermon
{

typedef void (*fn)(manager& mgr, context_ptr fc, pdu_iter s, pdu_iter e);

static fn tcp_port_handlers[65535] = {};


static bool tcp_handlers_initialised = false;


static void init_tcp_handlers(void)
{
    // Initialize all elements to null first
    for(uint16_t x = 0; x < 65535; x++)
    {
        tcp_port_handlers[x] = NULL;
    }

    // Now assign specific handlers
    tcp_port_handlers[21]  = &ftp::process;
    tcp_port_handlers[25]  = &smtp::process;
    tcp_port_handlers[53]  = &dns_over_tcp::process;
    tcp_port_handlers[110] = &pop3::process;
    tcp_port_handlers[220] = &imap::process;
    tcp_port_handlers[465] = &smtp_auth::process;
    tcp_port_handlers[993] = &imap_ssl::process;
    tcp_port_handlers[995] = &pop3_ssl::process;
    tcp_port_handlers[5060] = &sip::process;
    tcp_port_handlers[5061] = &sip_ssl::process;


    // Set flag to true to avoid the above
    // being repeatedly called in the future
    tcp_handlers_initialised = true;
}


static bool is_tcp_handlers_init(void)
{
    return tcp_handlers_initialised;
}


static void add_tcp_port_handler(uint16_t port, fn function)
{
    if (tcp_port_handlers[port] == NULL)
    {
        tcp_port_handlers[port] = function;
    }
    else
    {
//        throw exception("Handler already assigned to TCP port");
    }
}

static void remove_tcp_port_handler(uint16_t port)
{
    tcp_port_handlers[port] = NULL;
}


}; // End namespace

#endif

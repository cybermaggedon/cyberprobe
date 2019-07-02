////////////////////////////////////////////////////////////////////////////
//
// TCP Ports
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_TCP_PORTS_H
#define CYBERMON_TCP_PORTS_H


#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{

    class tcp_ports
    {

    private:

        typedef void (*fn)(manager& mgr, context_ptr fc, const pdu_slice& s);

        static fn port_handler[65535];

        static bool handlers_initialised;

    public:

        static void init_handlers(void);

        static bool is_handlers_init(void);

        static void add_port_handler(uint16_t port, fn function);

        static void remove_port_handler(uint16_t port);

        static bool has_port_handler(uint16_t port);

        static fn get_port_handler(uint16_t port);

    }; // End class

}; // End namespace

#endif

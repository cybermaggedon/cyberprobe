////////////////////////////////////////////////////////////////////////////
//
// TCP Ports
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_TCP_PORTS_H
#define CYBERMON_TCP_PORTS_H


#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>
#include <vector>

namespace cyberprobe {
namespace protocol {

    class tcp_ports
    {


    private:

        typedef void (*fn)(manager& mgr, context_ptr fc, const pdu_slice& s);

        static std::vector<fn> port_handler;

        static bool handlers_initialised;

    public:

        static void init_handlers(void);

        static bool is_handlers_init(void);

        static void add_port_handler(uint16_t port, fn function);

        static void remove_port_handler(uint16_t port);

        static bool has_port_handler(uint16_t port);

        static fn get_port_handler(uint16_t port);

    }; // End class

}
}

#endif

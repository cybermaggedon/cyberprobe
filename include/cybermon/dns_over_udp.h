
////////////////////////////////////////////////////////////////////////////
//
// DNS over UDP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_DNS_OVER_UDP_H
#define CYBERMON_DNS_OVER_UDP_H


#include "context.h"
#include "pdu.h"
#include "manager.h"


namespace cybermon
{

class dns_over_udp
{
    public:

    // DNS over UDP processing function.
    static void process(manager&, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif


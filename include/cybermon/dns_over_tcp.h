
////////////////////////////////////////////////////////////////////////////
//
// DNS over TCP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_DNS_OVER_TCP_H
#define CYBERMON_DNS_OVER_TCP_H


#include "context.h"
#include "pdu.h"
#include "manager.h"


namespace cybermon
{

class dns_over_tcp
{
    public:

    // DNS over TCP processing function.
    static void process(manager&, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif


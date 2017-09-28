
////////////////////////////////////////////////////////////////////////////
//
// DNS over TCP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_DNS_OVER_TCP_H
#define CYBERMON_DNS_OVER_TCP_H


#include "cybermon/context.h"
#include "cybermon/manager.h"
#include "cybermon/pdu.h"


namespace cybermon
{

class dns_over_tcp
{
    public:

    // DNS over TCP processing function.
    static void process(manager&, context_ptr c, const pdu_slice& s);
};

}; // End namespace

#endif


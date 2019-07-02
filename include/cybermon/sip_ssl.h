
////////////////////////////////////////////////////////////////////////////
//
// SIP SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SIP_SSL_H
#define CYBERMON_SIP_SSL_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
    class sip_ssl
    {
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}; // End namespace

#endif


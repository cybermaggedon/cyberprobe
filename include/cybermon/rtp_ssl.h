
////////////////////////////////////////////////////////////////////////////
//
// RTP SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_RTP_SSL_H
#define CYBERMON_RTP_SSL_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
    class rtp_ssl
    {
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}; // End namespace

#endif


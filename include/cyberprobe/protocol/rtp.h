
////////////////////////////////////////////////////////////////////////////
//
// RTP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_RTP_H
#define CYBERMON_RTP_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cybermon
{
    
    class rtp
    {
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}; // End namespace

#endif


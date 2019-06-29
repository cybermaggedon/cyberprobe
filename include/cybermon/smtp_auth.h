
////////////////////////////////////////////////////////////////////////////
//
// SMTP Authentication processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SMTP_AUTH_H
#define CYBERMON_SMTP_AUTH_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
    class smtp_auth
    {
    public:
        // SMTP_AUTH processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}; // End namespace

#endif


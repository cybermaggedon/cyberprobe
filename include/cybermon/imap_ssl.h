
////////////////////////////////////////////////////////////////////////////
//
// IMAP SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_IMAP_SSL_H
#define CYBERMON_IMAP_SSL_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
    class imap_ssl
    {
    public:

        // IMAP_SSL processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& s);
    };

}; // End namespace

#endif


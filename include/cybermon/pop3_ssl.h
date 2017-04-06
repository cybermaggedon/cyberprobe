
////////////////////////////////////////////////////////////////////////////
//
// POP3 SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_POP3_SSL_H
#define CYBERMON_POP3_SSL_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
class pop3_ssl
{
    public:

    // POP3_SSL processing.
    static void process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif



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

    static void process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif



////////////////////////////////////////////////////////////////////////////
//
// SIP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SIP_H
#define CYBERMON_SIP_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
class sip
{
  public:
    static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
};

}; // End namespace

#endif


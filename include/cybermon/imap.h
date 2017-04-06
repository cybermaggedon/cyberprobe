
////////////////////////////////////////////////////////////////////////////
//
// IMAP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_IMAP_H
#define CYBERMON_IMAP_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>


namespace cybermon
{
    
class imap
{
  public:

    // IMAP processing.
    static void process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif


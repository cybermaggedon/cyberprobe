
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "manager.h"
#include "context.h"
#include "pdu.h"

namespace analyser {

    typedef void (*process_fn)(manager&, context_ptr c, pdu_iter s, pdu_iter e);

};

#endif


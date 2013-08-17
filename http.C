
#include "http.h"

using namespace analyser;

// HTTP request processing function.
void http::process_request(manager& mgr, context_ptr c, 
			   pdu_iter s, pdu_iter e)
{
    mgr.connection_data(c, s, e);
}

// HTTP response processing function.
void http::process_response(manager& mgr, context_ptr c, pdu_iter s, 
			    pdu_iter e)
{
    mgr.connection_data(c, s, e);
}


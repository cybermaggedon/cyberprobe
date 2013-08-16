
#include "http.h"

using namespace analyser;

// HTTP request processing function.
void http::process_request(manager&, context_ptr c, 
			   pdu_iter s, pdu_iter e)
{
    std::cerr << "-- http request--" << std::endl;
}

// HTTP response processing function.
void http::process_response(manager&, context_ptr c, pdu_iter s, 
			    pdu_iter e)
{
    std::cerr << "-- http response--" << std::endl;
}


#ifndef OBSERVER_H
#define OBSERVER_H

#include "context.h"

namespace analyser {

    // Observer interface.  The observer interface is called when various
    // reportable events occur.
    class observer {
    public:
	
	// Connection-orientated.
	virtual void connection_up(const context_ptr cp) = 0;
	virtual void connection_down(const context_ptr cp) = 0;
	virtual void connection_data(const context_ptr cp,
				     pdu_iter s, pdu_iter e) = 0;

	// Connection-less
	virtual void datagram(const context_ptr cp,
			      pdu_iter s, pdu_iter e) = 0;

	typedef
	    std::map<std::string, std::pair<std::string,std::string> > 
	    http_hdr_t;

	// HTTP
	virtual void http_request(const context_ptr cp,
				  const std::string& method,
				  const std::string& url,
				  const analyser::observer::http_hdr_t& hdr,
				  pdu_iter body_start,
				  pdu_iter body_end) = 0;

	virtual void http_response(const context_ptr cp,
				   unsigned int code,
				   const std::string& status,
				   const http_hdr_t& hdr,
				   // URL of object, or "" if not known.
				   const std::string& url,
				   pdu_iter body_start,
				   pdu_iter body_end) = 0;


	virtual void trigger_up(const std::string& liid,
				const tcpip::address& trigger_address) = 0;
	virtual void trigger_down(const std::string& liid) = 0;
    };

};

#endif


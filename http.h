
////////////////////////////////////////////////////////////////////////////
//
// HTTP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <boost/regex.hpp>

#include <set>

#include "context.h"
#include "manager.h"
#include "serial.h"
#include "protocol.h"

namespace cybermon {

    // HTTP parser.  The request / response structures are almost identical,
    // so this parser make most use of the commonality.

    // Type of the header
    typedef 
	std::map<std::string, std::pair<std::string,std::string> > http_hdr_t;

    class http_parser {
    public:

	enum variant_t { REQUEST, RESPONSE };

    private:
	
	variant_t variant;

	enum {

	    // Request variant
	    IN_REQUEST_METHOD, IN_REQUEST_URL, IN_REQUEST_PROTOCOL,
	    POST_REQUEST_PROTOCOL_EXP_NL,

	    // Response variant
	    IN_RESPONSE_PROTOCOL, IN_RESPONSE_CODE, IN_RESPONSE_STATUS, 
	    POST_RESPONSE_STATUS_EXP_NL,

	    // Header
	    MAYBE_KEY, IN_KEY, POST_KEY_EXP_SPACE,
	    IN_VALUE, POST_VALUE_EXP_NL,
	    POST_HEADER_EXP_NL,

	    // Body, scanning for CRLF end.
	    IN_BODY, IN_BODY_AFTER_CR,
	    
	    // Body, just counting bytes.
	    COUNTING_DATA,
	    
	    // Body, chunked transfer encoding.
	    PRE_CHUNK_LENGTH,
	    IN_CHUNK_LENGTH,
	    POST_CHUNK_LENGTH_EXP_NL,
	    COUNTING_CHUNK_DATA,
	    POST_CHUNKED_EXP_NL

	} state;

	void reset_transaction() {
	    protocol = method = url = code = status = "";
	    body.clear();
	    header.clear();
	}

    public:

	http_parser(variant_t var) {
	    variant = var;
	    reset_transaction();

	    if (var == REQUEST)
		state = IN_REQUEST_METHOD;
	    else
		state = IN_RESPONSE_PROTOCOL;
	}

	void normalise_url(const std::string& host, const std::string url,
			   std::string& out) {

	    boost::match_results<std::string::const_iterator> what;

	    static const boost::regex already_normalised("[a-zA-Z]+:");

	    if (regex_search(url, what, already_normalised, 
			     boost::match_continuous)) {
		out = url;
		return;
	    }

	    out = "http://" + host + url;
	    
	}

	void complete_request(context_ptr c, manager& mgr);

	void complete_response(context_ptr c, manager& mgr);

	// Common to request and response.
	std::string protocol;

	// For the request.
	std::string method;
	std::string url;

	// For the response.
	std::string code;
	int codeval;
	std::string status;

	// Header key/val fields.
	http_hdr_t header;

	// Used when picking up key/value pairs.
	std::string key;
	std::string value;

	// Used for processing chunked transfer encoding.
	std::string chunk_length;
	
	// Used when reading data.
	unsigned long long content_remaining;

	// Payload is received here.
	pdu body;

	// Parse.
	void parse(context_ptr cp, pdu_iter s, pdu_iter e, manager& mgr);

    };
    
    // An HTTP request context.
    class http_request_context : public context, public http_parser {
      public:
	
	// Constructor.
        http_request_context(manager& m) : 
	context(m), http_parser(REQUEST) {
	}

	// Constructor, describing flow address and parent pointer.
        http_request_context(manager& m, const flow_address& a, 
			     context_ptr p) : 
	context(m), http_parser(REQUEST) { 
	    addr = a; parent = p; 
	}

	std::list<std::string> urls_requested;

	// Type.
	virtual std::string get_type() { return "http_request"; }

	typedef boost::shared_ptr<http_request_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new http_request_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, http_request_context::create);
	    ptr sp = boost::dynamic_pointer_cast<http_request_context>(cp);
	    return sp;
	}

    };

    // An HTTP response context.
    class http_response_context : public context, public http_parser {
      public:

	// Constructor.
        http_response_context(manager& m) :
	context(m), http_parser(RESPONSE) {
	}

	// Constructor, describing flow address and parent pointer.
        http_response_context(manager& m, const flow_address& a, 
			      context_ptr p) : 
	context(m), http_parser(RESPONSE) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "http_response"; }

	typedef boost::shared_ptr<http_response_context> ptr;

	static context_ptr create(manager& m, const flow_address& f, 
				  context_ptr par) {
	    context_ptr cp = context_ptr(new http_response_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, http_response_context::create);
	    ptr sp = boost::dynamic_pointer_cast<http_response_context>(cp);
	    return sp;
	}

    };

    class http {

    public:

	// HTTP request processing function.
	static void process_request(manager&, context_ptr c, 
				    pdu_iter s, pdu_iter e);

	// HTTP response processing function.
	static void process_response(manager&, context_ptr c, pdu_iter s, 
				     pdu_iter e);

    };

};

#endif



// Derived: http://www.jmarshall.com/easy/http

#include "address.h"
#include "http.h"
#include "ctype.h"
#include "manager.h"

using namespace cybermon;

// HTTP response processing function.
void http_parser::parse(context_ptr c, pdu_iter s, pdu_iter e, manager& mgr)
{

    while (s != e) {

	switch (state) {

	case http_parser::IN_REQUEST_METHOD:
	    if (*s == ' ')
		state = http_parser::IN_REQUEST_URL;
	    else
		method += *s;
	    break;

	case http_parser::IN_REQUEST_URL:
	    if (*s == ' ')
		state = http_parser::IN_REQUEST_PROTOCOL;
	    else
		url += *s;
	    break;

	case http_parser::IN_REQUEST_PROTOCOL:
	    if (*s == '\r')
		state = http_parser::POST_REQUEST_PROTOCOL_EXP_NL;
	    else
		protocol += *s;
	    break;

	case http_parser::POST_REQUEST_PROTOCOL_EXP_NL:
	    if (*s == '\n') {
		state = http_parser::MAYBE_KEY;
		key = value = "";
	    } else
		// Protocol violation!
		throw exception("HTTP protocol violation!");
	    break;

	case http_parser::IN_RESPONSE_PROTOCOL:
	    if (*s == ' ')
		state = http_parser::IN_RESPONSE_CODE;
	    else
		protocol += *s;
	    break;

	case http_parser::IN_RESPONSE_CODE:
	    if (*s == ' ')
		state = http_parser::IN_RESPONSE_STATUS;
	    else
		code += *s;
	    break;

	case http_parser::IN_RESPONSE_STATUS:
	    if (*s == '\r')
		state = http_parser::POST_RESPONSE_STATUS_EXP_NL;
	    else
		status += *s;
	    break;

	case http_parser::POST_RESPONSE_STATUS_EXP_NL:
	    if (*s == '\n') {
		state = http_parser::MAYBE_KEY;
		key = value = "";
	    } else {
		// Protocol violation!
		throw exception("HTTP protocol violation!");
	    }
	    break;

	case http_parser::MAYBE_KEY:
	    if (*s == '\r')
		state = http_parser::POST_HEADER_EXP_NL;
	    else {
		key += *s;
		state = http_parser::IN_KEY;
	    }
	    break;

	case http_parser::IN_KEY:
	    if (*s == ':')
		state = http_parser::POST_KEY_EXP_SPACE;
	    else
		key += *s;
	    break;

	case http_parser::POST_KEY_EXP_SPACE:
	    if (*s == ' ')
		state = http_parser::IN_VALUE;
	    else {
		// Protocol violation!
		throw exception("HTTP protocol violation!");
	    }
	    break;

	case http_parser::IN_VALUE:
	    if (*s == '\r') {

		 std::string lowerc;
		 std::transform(key.begin(), key.end(), back_inserter(lowerc), 
				::tolower);

		 header[lowerc] =
		     std::pair<std::string,std::string>(key, value);

		 key = "";
		 value = "";

		 state = http_parser::POST_VALUE_EXP_NL;
	     } else
		 value += *s;
	     break;

	 case http_parser::POST_VALUE_EXP_NL:
	     if (*s == '\n') {
		 state = http_parser::MAYBE_KEY;
		 key = value = "";
	     } else {
		 // Protocol violation!
		 throw exception("HTTP response protocol violation!");
	     }
	     break;

	 case http_parser::POST_HEADER_EXP_NL:
	     if (*s == '\n') {

 #ifdef USEFUL_DEBUG_I_GUESS
		 std::cerr << "code = " << fc->code << std::endl;
		 std::cerr << "status = " << fc->status << std::endl;
		 std::cerr << "Proto = " << fc->protocol << std::endl;
		 for(std::map<std::string, std::string>::iterator it = 
			 fc->header.begin();
		     it != fc->header.end();
		     it++) {
		     std::cerr << "(" << it->first << ") = (" << it->second
			       << ")" << std::endl;
		 }
 #endif

		 state = http_parser::IN_BODY;

		 if (header.find("content-type") == header.end()) {
		     // No body.

		     std::istringstream buf(code);
		     buf >> codeval;

		     if (variant == REQUEST)
			 complete_request(c, mgr);
		     else
			 complete_response(c, mgr);

		     if (variant == REQUEST)
			 state = http_parser::IN_REQUEST_METHOD;
		     else
			 state = http_parser::IN_RESPONSE_PROTOCOL;

		     reset_transaction();

		 } else if ((header.find("transfer-encoding") != 
			     header.end()) &&
			    (header["transfer-encoding"].second == "chunked")) {
		     state = http_parser::IN_CHUNK_LENGTH;
		 } else if (header.find("content-length") != header.end()) {
		     state = http_parser::COUNTING_DATA;
		     std::istringstream buf(header["content-length"].second);
		     buf >> std::dec >> content_remaining;
		 } else
		     // This state just looks for newline.
		     state = http_parser::IN_BODY;

	     } else {
		 // Protocol violation!
		 throw exception("HTTP response protocol violation!");
	     }
	     break;

	 case http_parser::IN_BODY:
	     if (*s == '\r')
		 state = http_parser::IN_BODY_AFTER_CR;
	    else
		body.push_back(*s);
	    break;

	case http_parser::IN_BODY_AFTER_CR:
	    if (*s == '\n') {
		body.push_back('\r');
		body.push_back(*s);
		state = http_parser::IN_BODY;
	    } else {

		std::istringstream buf(code);
		buf >> codeval;

		if (variant == REQUEST)
		    complete_request(c, mgr);
		else
		    complete_response(c, mgr);

		reset_transaction();
		
		// Start of next transaction.
		if (variant == REQUEST)
		    state = http_parser::IN_REQUEST_METHOD;
		else
		    state = http_parser::IN_RESPONSE_PROTOCOL;

	    }
	    break;

	case http_parser::COUNTING_DATA:

	    body.push_back(*s);
	    content_remaining--;

	    if (content_remaining == 0) {

		std::istringstream buf(code);
		buf >> codeval;

		if (variant == REQUEST)
		    complete_request(c, mgr);
		else
		    complete_response(c, mgr);

		reset_transaction();
		
		// Start of next transaction.
		if (variant == REQUEST)
		    state = http_parser::IN_REQUEST_METHOD;
		else
		    state = http_parser::IN_RESPONSE_PROTOCOL;

	    }
	    break;

	case http_parser::IN_CHUNK_LENGTH:
	    if (*s == '\r')
		state = http_parser::POST_CHUNK_LENGTH_EXP_NL;
	    else
		chunk_length += *s;
	    break;

	case http_parser::POST_CHUNK_LENGTH_EXP_NL:
	    if (*s == '\n') {
		std::istringstream buf(chunk_length);
		int chunk_length;
		buf >> std::hex >> content_remaining;

		if (content_remaining == 0) {
		    // FIXME: Need to handle the footer etc.

		    state = http_parser::POST_CHUNKED_EXP_NL;

		} else 

		    state = http_parser::COUNTING_CHUNK_DATA;

	    } else {
		throw exception("HTTP response protocol violation!");
	    }
	    break;

	case http_parser::POST_CHUNKED_EXP_NL:

	    if (*s == '\n') {
		// Transaction complete

		std::istringstream buf(code);
		buf >> codeval;
		
		if (variant == REQUEST)
		    complete_request(c, mgr);
		else
		    complete_response(c, mgr);

		reset_transaction();

		// Start of next transaction.
		if (variant == REQUEST)
		    state = http_parser::IN_REQUEST_METHOD;
		else
		    state = http_parser::IN_RESPONSE_PROTOCOL;


	    } else {
		// Otherwise skip over the CR, and possibly footer lines.
		// FIXME: Handle footer lines.
	    }
	    break;

	case http_parser::COUNTING_CHUNK_DATA:

	    body.push_back(*s);
	    content_remaining--;

	    if (content_remaining == 0) {

		std::istringstream buf(code);
		buf >> codeval;

		if (variant == REQUEST)
		    complete_request(c, mgr);
		else
		    complete_response(c, mgr);
		
		reset_transaction();

		// Start of next transaction.
		if (variant == REQUEST)
		    state = http_parser::IN_REQUEST_METHOD;
		else
		    state = http_parser::IN_RESPONSE_PROTOCOL;

	    }
	    break;

	default:
	    std::cerr << "State: "<< state << std::endl;
	    throw exception("A state not implemented.");

	}

	s++;

    }

}

// HTTP request processing function.
void http::process_request(manager& mgr, context_ptr c, 
			   pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, HTTP);
    dest.set(empty, TRANSPORT, HTTP);

    flow_address f(src, dest);

    http_request_context::ptr fc = http_request_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

// HTTP response processing function.
void http::process_response(manager& mgr, context_ptr c, 
			   pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, HTTP);
    dest.set(empty, TRANSPORT, HTTP);

    flow_address f(src, dest);

    http_response_context::ptr fc = http_response_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

void http_parser::complete_request(context_ptr c, manager& mgr)
{
	    
    std::string norm;
    
    // Convert host and URL into a fully normalised URL.
    normalise_url(header["host"].second, url, norm);

    // Stash the URL on a queue in our context structure.
    http_request_context::ptr sp = 
	boost::dynamic_pointer_cast<http_request_context>(c);
    sp->urls_requested.push_back(norm);

    // Raise an HTTP request event.
    mgr.http_request(c, method, url, header, 
		     body.begin(), body.end());
}

void http_parser::complete_response(context_ptr c, manager& mgr)
{

    // Get the 'reverse' HTTP flow.  This will be the HTTP request side.
    context_ptr rev = c->reverse.lock();

    std::string url;

    // If we have a reverse flow pointer...
    if (rev) {
	http_request_context::ptr sp_rev = 
	    boost::dynamic_pointer_cast<http_request_context>(rev);

	// ... then use it to get the URL of this HTTP response.
	sp_rev->lock.lock();
	url = sp_rev->urls_requested.front();
	sp_rev->urls_requested.pop_front();
	sp_rev->lock.unlock();
    }

    mgr.http_response(c, codeval, status, header, url, 
		      body.begin(), body.end());
}

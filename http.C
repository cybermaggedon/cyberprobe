
// Derived: http://www.jmarshall.com/easy/http

#include "address.h"
#include "http.h"
#include "ctype.h"

using namespace analyser;

// HTTP request processing function.
void http::process_request(manager& mgr, context_ptr c, 
			   pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.assign(empty, TRANSPORT, HTTP);
    dest.assign(empty, TRANSPORT, HTTP);

    flow f(src, dest);

    http_request_context::ptr fc = http_request_context::get_or_create(c, f);

    fc->lock.lock();

    while (s != e) {

//	std::cerr << "Request " << *s << " " << fc->state << std::endl;

	switch (fc->state) {

	case http_request_context::IN_METHOD:
	    if (*s == ' ')
		fc->state = http_request_context::IN_URL;
	    else
		fc->method += *s;
	    break;

	case http_request_context::IN_URL:
	    if (*s == ' ')
		fc->state = http_request_context::IN_PROTOCOL;
	    else
		fc->url += *s;
	    break;

	case http_request_context::IN_PROTOCOL:
	    if (*s == '\r')
		fc->state = http_request_context::POST_PROTOCOL_EXP_NL;
	    else
		fc->protocol += *s;
	    break;

	case http_request_context::POST_PROTOCOL_EXP_NL:
	    if (*s == '\n') {
		fc->state = http_request_context::MAYBE_KEY;
		fc->key = fc->value = "";
	    } else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP protocol violation!");
	    }
	    break;

	case http_request_context::MAYBE_KEY:
	    if (*s == '\r')
		fc->state = http_request_context::POST_HEADER_EXP_NL;
	    else {
		fc->key += tolower(*s);
		fc->state = http_request_context::IN_KEY;
	    }
	    break;

	case http_request_context::IN_KEY:
	    if (*s == ':')
		fc->state = http_request_context::POST_KEY_EXP_SPACE;
	    else
		fc->key += tolower(*s);
	    break;

	case http_request_context::POST_KEY_EXP_SPACE:
	    if (*s == ' ')
		fc->state = http_request_context::IN_VALUE;
	    else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP protocol violation!");
	    }
	    break;

	case http_request_context::IN_VALUE:
	    if (*s == '\r') {

		fc->header[fc->key] = fc->value;
		fc->key = "";
		fc->value = "";
		fc->state = http_request_context::POST_VALUE_EXP_NL;
	    } else
		fc->value += *s;
	    break;

	case http_request_context::POST_VALUE_EXP_NL:
	    if (*s == '\n') {
		fc->state = http_request_context::MAYBE_KEY;
		fc->key = fc->value = "";
	    } else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP request protocol violation!");
	    }
	    break;

	case http_request_context::POST_HEADER_EXP_NL:
	    if (*s == '\n') {

#ifdef USEFUL_DEBUG_I_GUESS
		std::cerr << "Method = " << fc->method << std::endl;
		std::cerr << "Url = " << fc->url << std::endl;
		std::cerr << "Proto = " << fc->protocol << std::endl;
		for(std::map<std::string, std::string>::iterator it = 
			fc->header.begin();
		    it != fc->header.end();
		    it++) {
		    std::cerr << "(" << it->first << ") = (" << it->second
			      << ")" << std::endl;
		}
#endif

		std::map<std::string,std::string>& header = fc->header;

		if (header.find("content-type") == header.end()) {

		    // No body.

		    mgr.http_request(fc, fc->method, fc->url, fc->header, 
				     fc->body.begin(), fc->body.end());

		    fc->state = http_request_context::IN_METHOD;

		    fc->method = fc->url = fc->protocol = "";
		    header.clear();

		} else if (header.find("content-length") != header.end()) {
		    fc->state = http_request_context::COUNTING_DATA;
		    std::istringstream buf(header["content-length"]);
		    buf >> std::dec >> fc->content_remaining;
		} else
		    // This state just looks for newline.
		    fc->state = http_request_context::IN_DATA;

	    } else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP request protocol violation!");
	    }
	    break;

	case http_request_context::IN_DATA:
	    if (*s == '\r')
		fc->state = http_request_context::IN_DATA_MAYBE_END;
	    else
		fc->body.push_back(*s);
	    break;

	case http_request_context::IN_DATA_MAYBE_END:
	    if (*s == '\n') {
		fc->body.push_back('\r');
		fc->body.push_back(*s);
		fc->state = http_request_context::IN_DATA;
	    } else {
		
		mgr.http_request(fc, fc->method, fc->url, fc->header, 
				 fc->body.begin(), fc->body.end());

		fc->method = fc->url = fc->protocol = "";
		fc->header.clear();
		
		// Start of next transaction.
		fc->state = http_request_context::IN_METHOD;

	    }
	    break;

	case http_request_context::COUNTING_DATA:

	    fc->body.push_back(*s);
	    fc->content_remaining--;

	    if (fc->content_remaining == 0) {
		
		mgr.http_request(fc, fc->method, fc->url,
				 fc->header, fc->body.begin(), fc->body.end());

		fc->method = fc->url = fc->protocol = "";
		fc->header.clear();
		
		// Start of next transaction.
		fc->state = http_request_context::IN_METHOD;

	    }
	    break;

	default:
	    std::cerr << "XXX state "<< fc->state << std::endl;
	    fc->lock.unlock();
	    throw exception("A state not implemented.");

	}

	s++;

    }

    fc->lock.unlock();

}

// HTTP response processing function.
void http::process_response(manager& mgr, context_ptr c, 
			   pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.assign(empty, TRANSPORT, HTTP);
    dest.assign(empty, TRANSPORT, HTTP);

    flow f(src, dest);

    http_response_context::ptr fc = http_response_context::get_or_create(c, f);

    fc->lock.lock();

    while (s != e) {

	switch (fc->state) {

	case http_response_context::IN_PROTOCOL:
	    if (*s == ' ')
		fc->state = http_response_context::IN_CODE;
	    else
		fc->protocol += *s;
	    break;

	case http_response_context::IN_CODE:
	    if (*s == ' ')
		fc->state = http_response_context::IN_STATUS;
	    else
		fc->code += *s;
	    break;

	case http_response_context::IN_STATUS:
	    if (*s == '\r')
		fc->state = http_response_context::POST_STATUS_EXP_NL;
	    else
		fc->status += *s;
	    break;

	case http_response_context::POST_STATUS_EXP_NL:
	    if (*s == '\n') {
		fc->state = http_response_context::MAYBE_KEY;
		fc->key = fc->value = "";
	    } else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP protocol violation!");
	    }
	    break;

	case http_response_context::MAYBE_KEY:
	    if (*s == '\r')
		fc->state = http_response_context::POST_HEADER_EXP_NL;
	    else {
		fc->key += tolower(*s);
		fc->state = http_response_context::IN_KEY;
	    }
	    break;

	case http_response_context::IN_KEY:
	    if (*s == ':')
		fc->state = http_response_context::POST_KEY_EXP_SPACE;
	    else
		fc->key += tolower(*s);
	    break;

	case http_response_context::POST_KEY_EXP_SPACE:
	    if (*s == ' ')
		fc->state = http_response_context::IN_VALUE;
	    else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP protocol violation!");
	    }
	    break;

	case http_response_context::IN_VALUE:
	    if (*s == '\r') {

		fc->header[fc->key] = fc->value;
		fc->key = "";
		fc->value = "";
		fc->state = http_response_context::POST_VALUE_EXP_NL;
	    } else
		fc->value += *s;
	    break;

	case http_response_context::POST_VALUE_EXP_NL:
	    if (*s == '\n') {
		fc->state = http_response_context::MAYBE_KEY;
		fc->key = fc->value = "";
	    } else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP response protocol violation!");
	    }
	    break;

	case http_response_context::POST_HEADER_EXP_NL:
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

		std::map<std::string,std::string>& header = fc->header;
		fc->state = http_response_context::IN_DATA;

		if (header.find("content-type") == header.end()) {
		    // No body.

		    std::istringstream buf(fc->code);
		    unsigned int code;
		    buf >> code;

		    mgr.http_response(fc, code, fc->status, fc->header, 
				      fc->body.begin(), fc->body.end());

		    fc->state = http_response_context::IN_PROTOCOL;

		    fc->protocol = fc->code = fc->status = "";
		    header.clear();

		} else if ((header.find("transfer-encoding") != header.end()) &&
		    (header["transfer-encoding"] == "chunked")) {
		    fc->state = http_response_context::IN_CHUNK_LENGTH;
		} else if (header.find("content-length") != header.end()) {
		    fc->state = http_response_context::COUNTING_DATA;
		    std::istringstream buf(header["content-length"]);
		    buf >> std::dec >> fc->content_remaining;
		} else
		    // This state just looks for newline.
		    fc->state = http_response_context::IN_DATA;

	    } else {
		// Protocol violation!
		fc->lock.unlock();
		throw exception("HTTP response protocol violation!");
	    }
	    break;

	case http_response_context::IN_DATA:
	    if (*s == '\r')
		fc->state = http_response_context::IN_DATA_MAYBE_END;
	    else
		fc->body.push_back(*s);
	    break;

	case http_response_context::IN_DATA_MAYBE_END:
	    if (*s == '\n') {
		fc->body.push_back('\r');
		fc->body.push_back(*s);
		fc->state = http_response_context::IN_DATA;
	    } else {

		std::istringstream buf(fc->code);
		unsigned int code;
		buf >> code;

		mgr.http_response(fc, code, fc->status, fc->header, 
				  fc->body.begin(), fc->body.end());

		fc->protocol = fc->code = fc->status = "";
		fc->header.clear();
		
		// Start of next transaction.
		fc->state = http_response_context::IN_PROTOCOL;

	    }
	    break;

	case http_response_context::COUNTING_DATA:

	    fc->body.push_back(*s);
	    fc->content_remaining--;

	    if (fc->content_remaining == 0) {

		std::istringstream buf(fc->code);
		unsigned int code;
		buf >> code;

		mgr.http_response(fc, code, fc->status, fc->header, 
				  fc->body.begin(), fc->body.end());
		
		// FIXME: Raise event here.

		fc->protocol = fc->code = fc->status = "";
		fc->header.clear();
		
		// Start of next transaction.
		fc->state = http_response_context::IN_PROTOCOL;

	    }
	    break;

	case http_response_context::IN_CHUNK_LENGTH:
	    if (*s == '\r')
		fc->state = http_response_context::POST_CHUNK_LENGTH_EXP_NL;
	    else
		fc->chunk_length += *s;
	    break;

	case http_response_context::POST_CHUNK_LENGTH_EXP_NL:
	    if (*s == '\n') {
		std::istringstream buf(fc->chunk_length);
		int chunk_length;
		buf >> std::hex >> fc->content_remaining;

		if (fc->content_remaining == 0) {
		    // FIXME: Need to handle the footer etc.

		    fc->state = http_response_context::POST_CHUNKED_EXP_NL;

		} else 

		    fc->state = http_response_context::COUNTING_CHUNK_DATA;

	    } else {
		fc->lock.unlock();
		throw exception("HTTP response protocol violation!");
	    }
	    break;

	case http_response_context::POST_CHUNKED_EXP_NL:

	    if (*s == '\n') {
		// Transaction complete

		std::istringstream buf(fc->code);
		unsigned int code;
		buf >> code;

		mgr.http_response(fc, code, fc->status, fc->header, 
				  fc->body.begin(), fc->body.end());
	    } else {
		// Otherwise skip over the CR, and possibly footer lines.
		// FIXME: Handle footer lines.
	    }
	    break;

	case http_response_context::COUNTING_CHUNK_DATA:

	    fc->body.push_back(*s);
	    fc->content_remaining--;

	    if (fc->content_remaining == 0) {

		std::istringstream buf(fc->code);
		unsigned int code;
		buf >> code;

		mgr.http_response(fc, code, fc->status, fc->header, 
				  fc->body.begin(), fc->body.end());
		
		// FIXME: Raise event here.

		fc->protocol = fc->code = fc->status = "";
		fc->header.clear();
		
		// Start of next transaction.
		fc->state = http_response_context::IN_PROTOCOL;

	    }
	    break;

	default:
	    std::cerr << "YYY state "<< fc->state << std::endl;
	    fc->lock.unlock();
	    throw exception("A state not implemented.");

	}

	s++;

    }

    fc->lock.unlock();

}

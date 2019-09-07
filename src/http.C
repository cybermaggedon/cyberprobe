
// Derived: http://www.jmarshall.com/easy/http

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/http.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/unrecognised.h>
#include <cyberprobe/event/event_implementations.h>

#include <ctype.h>
#include <sstream>
#include <iomanip>

using namespace cyberprobe::protocol;
using namespace cyberprobe::analyser;

// HTTP response processing function.
void http_parser::parse(context_ptr c, const pdu_slice& sl, manager& mgr)
{

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    while (s != e) {

#ifdef USEFUL_DEBUG_I_GUESS
	std::cerr << state << std::endl;
	for(pdu_iter i = s; i < e; i++) {
	    std::cerr << (char) *i;
	}
	std::cerr << std::endl;
#endif


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
	    } else {
		// This would be a protocol violation, but much more likely to be
		// a HTTP CONNECT session, but we've missed the CONNECT or 200
		// response. Assume it is binary data
                throw exception("HTTP protocol violation! POST_REQUEST_PROTOCOL_EXP_NL");
	    }
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
		// This would be a protocol violation, but much more likely
		// to be a HTTP CONNECT session, but we've missed the
		// CONNECT or 200
		// response. Assume it is binary data
                throw exception("HTTP protocol violation! POST_RESPONSE_STATUS_EXP_NL");
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
	    if (*s == ':') {
		state = http_parser::POST_KEY_EXP_SPACE;
	    } else
		key += *s;
	    break;

	case http_parser::POST_KEY_EXP_SPACE:
	    if (*s == ' ')
		state = http_parser::IN_VALUE;
	    else {
		// This would be a protocol violation, but much more likely to be
		// a HTTP CONNECT session, but we've missed the CONNECT or 200
		// response. Assume it is binary data
                throw exception("HTTP protocol violation! POST_KEY_EXP_SPACE");
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
                // This would be a protocol violation, but much more likely to be
                // a HTTP CONNECT session, but we've missed the CONNECT or 200
                // response. Assume it is binary data
                throw exception("HTTP protocol violation! POST_VALUE_EXP_NL");
            }
            break;

        case http_parser::POST_HEADER_EXP_NL:
            if (*s == '\n') {

#ifdef USEFUL_DEBUG_I_GUESS
                std::cerr << "code = " << code << std::endl;
                std::cerr << "status = " << status << std::endl;
                std::cerr << "Proto = " << protocol << std::endl;
#endif

                std::istringstream buf(code);
                buf >> codeval;

                state = http_parser::IN_BODY;

                if (header.find("content-type") == header.end()) {
                    // No body.

                    if (variant == REQUEST)
                        complete_request(c, sl.time, mgr);
                    else
                        complete_response(c, sl.time, mgr);

                    if (variant == REQUEST)
                        state = http_parser::IN_REQUEST_METHOD;
                    else
                        state = http_parser::IN_RESPONSE_PROTOCOL;

                    reset_transaction();

                } else if ((header.find("transfer-encoding") !=
                            header.end()) &&
                           (header["transfer-encoding"].second == "chunked")) {
                    chunk_length = "";
                    state = http_parser::IN_CHUNK_LENGTH;
                } else if (header.find("content-length") != header.end()) {

                    std::istringstream b2(header["content-length"].second);
                    b2 >> std::dec >> content_remaining;

                    // Deal with zero-length payload case.  Transaction stops
                    // here.
                    if (content_remaining == 0) {
                        if (variant == REQUEST)
                            complete_request(c, sl.time, mgr);
                        else
                            complete_response(c, sl.time, mgr);
                        reset_transaction();

                        // Start of next transaction.
                        if (variant == REQUEST)
                            state = http_parser::IN_REQUEST_METHOD;
                        else
                            state = http_parser::IN_RESPONSE_PROTOCOL;

                    } else {
                        state = http_parser::COUNTING_DATA;
                    }

                } else
                    // This state just looks for newline.
                    state = http_parser::IN_BODY;

            } else {
                // This would be a protocol violation, but much more likely to be
                // a HTTP CONNECT session, but we've missed the CONNECT or 200
                // response. Assume it is binary data
                throw exception("HTTP protocol violation! POST_HEADER_EXP_NL");
            }
            break;

	case http_parser::PRE_CHUNK_LENGTH:
	    // Skip CRLF
	    if (*s == '\n') {
		chunk_length = "";
		state = http_parser::IN_CHUNK_LENGTH;
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

		if (variant == REQUEST)
		    complete_request(c, sl.time, mgr);
		else
		    complete_response(c, sl.time, mgr);

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

		if (variant == REQUEST)
		    complete_request(c, sl.time, mgr);
		else
		    complete_response(c, sl.time, mgr);

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
		buf >> std::hex >> content_remaining;

		if (content_remaining == 0) {
		    // FIXME: Need to handle the footer etc.

		    state = http_parser::POST_CHUNKED_EXP_NL;

		} else

		    state = http_parser::COUNTING_CHUNK_DATA;

            } else {
                // This would be a protocol violation, but much more likely to be
                // a HTTP CONNECT session, but we've missed the CONNECT or 200
                // response. Assume it is binary data
                throw exception("HTTP protocol violation! POST_CHUNK_LENGTH_EXP_NL");
	    }
	    break;

	case http_parser::POST_CHUNKED_EXP_NL:

	    if (*s == '\n') {
		// Transaction complete

		if (variant == REQUEST)
		    complete_request(c, sl.time, mgr);
		else
		    complete_response(c, sl.time, mgr);

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

		chunk_length = "";
		state = http_parser::PRE_CHUNK_LENGTH;
		break;

/*
  std::istringstream buf(code);
  buf >> codeval;

  if (variant == REQUEST)
  complete_request(c, sl.time, mgr);
  else
  complete_response(c, sl.time, mgr);

  reset_transaction();

  // Start of next transaction.
  if (variant == REQUEST)
  state = http_parser::IN_REQUEST_METHOD;
  else
  state = http_parser::IN_RESPONSE_PROTOCOL;
*/

	    }
	    break;

	default:
	    throw exception("An HTTP parsing state not implemented!");

	}

	s++;

    }

}

// HTTP request processing function.
void http::process_request(manager& mgr, context_ptr c,
			   const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, HTTP);
    dest.set(empty, TRANSPORT, HTTP);

    flow_address f(src, dest, sl.direc);

    http_request_context::ptr fc = http_request_context::get_or_create(c, f);

    // if this session is streaming just send unrecognised_stream
    if (fc->streaming) {
        unrecognised::process_unrecognised_stream(mgr, fc, sl);
    } else {
        // process HTTP packet
	try {
	    std::lock_guard<std::mutex> lock(fc->mutex);
	    fc->parse(fc, sl, mgr);
	} catch (cyberprobe::exception& e) {
	    unrecognised::process_unrecognised_stream(mgr, fc, sl);
	}
    }

}

// HTTP response processing function.
void http::process_response(manager& mgr, context_ptr c,
			    const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, HTTP);
    dest.set(empty, TRANSPORT, HTTP);

    flow_address f(src, dest, sl.direc);

    http_response_context::ptr fc = http_response_context::get_or_create(c, f);

    // if this session is streaming just send unrecognised_stream
    if (fc->streaming) {
        unrecognised::process_unrecognised_stream(mgr, c, sl);
    } else {
        // process HTTP packet
	try {
	    std::lock_guard<std::mutex> lock(fc->mutex);
	    fc->parse(fc, sl, mgr);
	} catch (cyberprobe::exception& e) {
	    unrecognised::process_unrecognised_stream(mgr, fc, sl);
	}
    }

}

void http_parser::complete_request(context_ptr c, const pdu_time& time,
				   manager& mgr)
{

    std::string norm;

    // Convert host and URL into a fully normalised URL.
    if (method == "CONNECT")
	norm = url;
    else
	normalise_url(header["host"].second, url, norm);

    // Stash the URL on a queue in our context structure.
    http_request_context::ptr sp =
	std::dynamic_pointer_cast<http_request_context>(c);
    sp->urls_requested.push_back(norm);

    // if this is a connect message we need to flag it in the context
    if (method == "CONNECT") {
        sp->streaming_requested = true;
    }

    // Raise an HTTP request event.
    auto ev =
	std::make_shared<event::http_request>(c, method, norm, header,
					      body.begin(), body.end(), time);
    mgr.handle(ev);

}

void http_parser::complete_response(context_ptr c, const pdu_time& time,
				    manager& mgr)
{

    // Get the 'reverse' HTTP flow.  This will be the HTTP request side.
    context_ptr rev = c->reverse.lock();

    std::string url;

    // If we have a reverse flow pointer...
    if (rev) {
	http_request_context::ptr sp_rev =
	    std::dynamic_pointer_cast<http_request_context>(rev);

	// ... then use it to get the URL of this HTTP response.
	std::lock_guard<std::mutex> lock(sp_rev->mutex);

	// If list is not empty, get the URL on the URL queue to be the
	// URL of this payload.
	if (sp_rev->urls_requested.size() > 0) {
	    url = sp_rev->urls_requested.front();
	    sp_rev->urls_requested.pop_front();
	}

        // check if the request was to start streaming
        if (sp_rev->streaming_requested) {
            sp_rev->streaming_requested = false;
            // any 2XX code is valid
            if (code[0] == '2') {
                sp_rev->streaming = true;

                http_response_context::ptr rc =
                    std::dynamic_pointer_cast<http_response_context>(c);
                rc->streaming = true;
            }
        }

    }

    auto ev =
	std::make_shared<event::http_response>(c, codeval, status, header, url,
					       body.begin(), body.end(), time);
    mgr.handle(ev);

}


#include "address.h"
#include "smtp.h"
#include "ctype.h"
#include "manager.h"
#include "hexdump.h"

#include <iostream>

using namespace cybermon;

// SMTP client processing function.
void smtp::process_client(manager& mgr, context_ptr c, 
			  pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, SMTP);
    dest.set(empty, TRANSPORT, SMTP);

    flow_address f(src, dest);

    smtp_client_context::ptr fc = smtp_client_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

// SMTP server processing function.
void smtp::process_server(manager& mgr, context_ptr c, 
			  pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, SMTP);
    dest.set(empty, TRANSPORT, SMTP);

    flow_address f(src, dest);

    smtp_server_context::ptr fc = smtp_server_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

void smtp_client_parser::parse(context_ptr cp, pdu_iter s, pdu_iter e,
			       manager& mgr)
{ 
    
    while (s != e) {

	switch (state) {

	case smtp_client_parser::IN_COMMAND:
	    
	    if (*s == '\r') {
		state = smtp_client_parser::EXP_NL;
		break;
	    }

	    command += *s;
	    break;

	case smtp_client_parser::EXP_NL:

	    if (*s == '\n') {

		mgr.smtp_command(cp, command);

		if (command == "DATA") {
		    state = smtp_client_parser::IN_DATA;
		    data.clear();
		    command = "";
		    break;
		}
		
		state = smtp_client_parser::IN_COMMAND;
		command = "";
		break;
	    }

	    throw exception("An SMTP client protocol violation: Expecting LF");

	case smtp_client_parser::IN_DATA:

	    data.push_back(*s);
	    
	    if (data.size() < exp_terminator.length())
		continue;

	    if (std::equal(exp_terminator.begin(), exp_terminator.end(),
			   data.end() - exp_terminator.size())) {

		data.erase(data.end() - exp_terminator.size(),
			   data.end());

		state = smtp_client_parser::IN_COMMAND;

		mgr.smtp_data(cp, data.begin(), data.end());

	    }

	    break;

	default:
	    throw exception("An SMTP client parsing state not implemented!");

	}

	s++;

    }

}


void smtp_server_parser::parse(context_ptr cp, pdu_iter s, pdu_iter e,
			       manager& mgr)
{ 
    
    while (s != e) {

	switch (state) {

	case smtp_server_parser::IN_STATUS_CODE:
	    
	    if (*s == ' ' || *s == '-') {
		if (status_str.length() != 3)
		    throw exception("SMTP server protocol violation: "
				    "Expect 3-char status");
		cont = (*s == '-');
		state = smtp_server_parser::IN_TEXT;
		break;
	    }

	    if (status_str.length() == 3)
		throw exception("SMTP server protocol violation: "
				"Status code too long");

	    if (*s < '0' || *s > '9')
		throw exception("SMTP server protocol violation: "
				"Status code not numeric");

	    status_str += *s;

	    break;

	case smtp_server_parser::IN_TEXT:
	    
	    if (*s == '\r') {
		state = smtp_server_parser::EXP_NL;
		break;
	    }

	    text += *s;
	    break;

	case smtp_server_parser::EXP_NL:

	    if (*s == '\n') {

		std::istringstream buf(status_str);
		buf >> std::dec >> status;

		if (first) {
		    last_status = status;
		} else {
		    if (status != last_status)
			throw exception("SMTP server protocol violation");
		}

		texts.push_back(text);

		if (!cont) {

		    // Do something with the data.

		    mgr.smtp_response(cp, status, texts);

		    first = true;
		    texts.clear();

		}

		status_str = "";
		text = "";

		state = smtp_server_parser::IN_STATUS_CODE;
		break;
	    }

	    throw exception("SMTP server protocol violation");

	default:
	    throw exception("An SMTP server parsing state not implemented!");

	}

	s++;

    }

}


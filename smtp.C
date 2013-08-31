
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
//	hexdump::dump(s, e, std::cout);
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
//	hexdump::dump(s, e, std::cout);
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

		std::cerr << "Command: " << command << std::endl;
		std::cerr << std::endl;

		if (command == "DATA") {
		    state = smtp_client_parser::IN_DATA;
		    data = "";
		    command = "";
		    break;
		}
		
		state = smtp_client_parser::IN_COMMAND;
		command = "";
		break;
	    }

	    throw exception("An SMTP client protocol violation: Expecting LF");

	case smtp_client_parser::IN_DATA:

	    data += *s;
	    
	    if (data.length() < exp_terminator.length())
		continue;

	    {

	    std::string last_five = 
		data.substr(data.length() - exp_terminator.length(), 
			    data.length());

	    if (last_five == exp_terminator) {
		data = data.substr(0, data.length() - exp_terminator.length());
		state = smtp_client_parser::IN_COMMAND;
		std::cerr << "Data: Got " << data.length() << " bytes."
			  << std::endl;
		std::cerr << std::endl;
	    }

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

		    std::cerr << "Status: " << std::dec << status << std::endl;
		    for(std::list<std::string>::iterator it = texts.begin();
			it != texts.end();
			it++) {
			std::cerr << "Text: " << *it << std::endl;
		    }
		    std::cerr << std::endl;

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


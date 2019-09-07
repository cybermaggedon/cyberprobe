
#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/smtp.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/event/event_implementations.h>

#include <regex>
#include <iostream>

#include <ctype.h>

using namespace cyberprobe::protocol;


// SMTP processing function.
void smtp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    if (c->addr.dest.get_uint16() == 25)
        {
            smtp::process_client(mgr, c, sl);
            return;
        }
    else if (c->addr.src.get_uint16() == 25)
        {
            smtp::process_server(mgr, c, sl);
            return;
        }
    else
        {
            throw exception("Trying to handle SMTP but neither port number is 25");
        }
}

// SMTP client processing function.
void smtp::process_client(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, SMTP);
    dest.set(empty, TRANSPORT, SMTP);

    flow_address f(src, dest, sl.direc);

    smtp_client_context::ptr fc = smtp_client_context::get_or_create(c, f);

    std::lock_guard<std::mutex> lock(fc->mutex);

    fc->parse(fc, sl, mgr);

}

// SMTP server processing function.
void smtp::process_server(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, SMTP);
    dest.set(empty, TRANSPORT, SMTP);

    flow_address f(src, dest, sl.direc);

    smtp_server_context::ptr fc = smtp_server_context::get_or_create(c, f);

    std::lock_guard<std::mutex> lock(fc->mutex);

    fc->parse(fc, sl, mgr);

}

void smtp_client_parser::parse(context_ptr cp, const pdu_slice& sl,
			       manager& mgr)
{ 

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;
    
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

		auto ev =
		    std::make_shared<event::smtp_command>(cp, command, sl.time);
		mgr.handle(ev);

		static const std::regex 
		    mail_from(" *MAIL +[Ff][Rr][Oo][Mm] *: *<([^ ]+)>",
			      std::regex::extended);

		static const std::regex 
		    rcpt_to(" *RCPT +[Tt][Oo] *: *<([^ ]+)>",
			    std::regex::extended);

		static const std::regex 
		    data_cmd(" *DATA *", std::regex::extended);

		static const std::regex 
		    rset_cmd(" *RSET *", std::regex::extended);

		std::match_results<std::string::const_iterator> what;

		if (regex_search(command, what, mail_from, 
				 std::regex_constants::match_continuous)) {
		    from = what[1];
		}

		if (regex_search(command, what, rcpt_to, 
				 std::regex_constants::match_continuous)) {
		    to.push_back(what[1]);
		}

		if (regex_search(command, what, data_cmd, 
				 std::regex_constants::match_continuous)) {
		    state = smtp_client_parser::IN_DATA;
		    data.clear();
		    command = "";
		    break;
		}

		if (regex_search(command, what, rset_cmd, 
				 std::regex_constants::match_continuous)) {
		    state = smtp_client_parser::IN_COMMAND;
		    data.clear();
		    command = "";
		    from = "";
		    to.clear();
		    break;
		}
		
		state = smtp_client_parser::IN_COMMAND;
		command = "";
		break;
	    }

	    throw exception("An SMTP client protocol violation: Expecting LF");

	case smtp_client_parser::IN_DATA:

	    data.push_back(*s);
	    
	    if (data.size() < exp_terminator.length()) {
		s++;
		continue;
	    }

	    if (std::equal(exp_terminator.begin(), exp_terminator.end(),
			   data.end() - exp_terminator.size())) {

		data.erase(data.end() - exp_terminator.size(),
			   data.end());

		state = smtp_client_parser::IN_COMMAND;

		// FIXME: Need to turn the data into something more useful
		// i.e. RFC822 decode.
		auto ev =
		    std::make_shared<event::smtp_data>(cp, from, to,
						       data.begin(),
						       data.end(), sl.time);
		mgr.handle(ev);

		from = "";
		to.clear();

	    }

	    break;

	default:
	    throw exception("An SMTP client parsing state not implemented!");

	}

	s++;

    }

}


void smtp_server_parser::parse(context_ptr cp, const pdu_slice& sl,
			       manager& mgr)
{ 

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;
    
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

		    auto ev =
			std::make_shared<event::smtp_response>(cp, status,
							       texts, sl.time);
		    mgr.handle(ev);

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


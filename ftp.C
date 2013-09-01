
#include "address.h"
#include "ftp.h"
#include "ctype.h"
#include "manager.h"

#include <iostream>

using namespace cybermon;

// FTP client processing function.
void ftp::process_client(manager& mgr, context_ptr c, 
			 pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, FTP);
    dest.set(empty, TRANSPORT, FTP);

    flow_address f(src, dest);

    ftp_client_context::ptr fc = ftp_client_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

// FTP server processing function.
void ftp::process_server(manager& mgr, context_ptr c, 
			 pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, FTP);
    dest.set(empty, TRANSPORT, FTP);

    flow_address f(src, dest);

    ftp_server_context::ptr fc = ftp_server_context::get_or_create(c, f);

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

void ftp_client_parser::parse(context_ptr cp, pdu_iter s, pdu_iter e,
			       manager& mgr)
{ 

    while (s != e) {

	switch (state) {

	case ftp_client_parser::IN_COMMAND:
	    
	    if (*s == '\r') {
		state = ftp_client_parser::EXP_NL;
		break;
	    }

	    command += *s;
	    break;

	case ftp_client_parser::EXP_NL:

	    if (*s == '\n') {

		static const boost::regex 
		    user_cmd(" *USER +(.*)$", boost::regex::extended);
		    
		static const boost::regex 
		    pass_cmd(" *PASS +(.*)$", boost::regex::extended);
		    
		boost::match_results<std::string::const_iterator> what;

		if (regex_search(command, what, user_cmd, 
				 boost::match_continuous)) {
//		    std::cerr << "User: " << what[1] << std::endl;

		}

		if (regex_search(command, what, pass_cmd, 
				 boost::match_continuous)) {
//		    std::cerr << "Password: " << what[1] << std::endl;

		}

		mgr.ftp_command(cp, command);

/*
		mgr.ftp_command(cp, command);

		static const boost::regex 
		    mail_from(" *MAIL +[Ff][Rr][Oo][Mm] *: *<([^ ]+)>",
			      boost::regex::extended);

		static const boost::regex 
		    rcpt_to(" *RCPT +[Tt][Oo] *: *<([^ ]+)>",
			    boost::regex::extended);

		static const boost::regex 
		    data_cmd(" *DATA *", boost::regex::extended);

		static const boost::regex 
		    rset_cmd(" *RSET *", boost::regex::extended);

		boost::match_results<std::string::const_iterator> what;

		if (regex_search(command, what, mail_from, 
				 boost::match_continuous)) {
		    from = what[1];
		}

		if (regex_search(command, what, rcpt_to, 
				 boost::match_continuous)) {
		    to.push_back(what[1]);
		}

		if (regex_search(command, what, data_cmd, 
				 boost::match_continuous)) {
		    state = ftp_client_parser::IN_DATA;
		    data.clear();
		    command = "";
		    break;
		}

		if (regex_search(command, what, rset_cmd, 
				 boost::match_continuous)) {
		    state = ftp_client_parser::IN_COMMAND;
		    data.clear();
		    command = "";
		    from = "";
		    to.clear();
		    break;
		}

*/
		
		state = ftp_client_parser::IN_COMMAND;
		command = "";
		break;
	    }

	    throw exception("An FTP client protocol violation: Expecting LF");

	case ftp_client_parser::IN_DATA:

	    data.push_back(*s);
	    
	    if (data.size() < exp_terminator.length())
		continue;

	    if (std::equal(exp_terminator.begin(), exp_terminator.end(),
			   data.end() - exp_terminator.size())) {

		data.erase(data.end() - exp_terminator.size(),
			   data.end());

		state = ftp_client_parser::IN_COMMAND;

		//mgr.ftp_data(cp, from, to, data.begin(), data.end());

		from = "";
		to.clear();

	    }

	    break;

	default:
	    throw exception("An FTP client parsing state not implemented!");

	}

	s++;

    }

}


void ftp_server_parser::parse(context_ptr cp, pdu_iter s, pdu_iter e,
			       manager& mgr)
{ 

    while (s != e) {

	switch (state) {

	case ftp_server_parser::IN_STATUS:

	    if (*s == ' ') {

		std::istringstream buf(status_str);
		buf >> std::dec >> status;

		cont = false;
		state = ftp_server_parser::IN_TEXT;
		break;

	    }

	    if (*s == '-') {

		std::istringstream buf(status_str);
		buf >> std::dec >> status;

		cont = true;
		state = ftp_server_parser::IN_TEXT;
		break;

	    }

	    if (status_str.length() == 3)
		throw exception("FTP server protocol violation: "
				"Status code length");

	    status_str += *s;
	    break;

	case ftp_server_parser::IN_TEXT:

	    if (*s == '\r') {
		state = ftp_server_parser::POST_TEXT_EXP_NL;
		break;
	    }
	    
	    response += *s;
	    break;

	case ftp_server_parser::POST_TEXT_EXP_NL:
	    
	    if (*s == '\n') {

		responses.push_back(response);
		
		if (!cont) {

		    static const boost::regex 
			passive_cmd(".*\\(([0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+)\\)",
				    boost::regex::extended);
		    
		    boost::match_results<std::string::const_iterator> what;

		    if (regex_search(response, what, passive_cmd, 
				     boost::match_continuous)) {

			std::istringstream buf(what[1]);
			
			unsigned int h1, h2, h3, h4, p1, p2;
			
			buf >> std::dec;
			buf >> h1; buf.get();
			buf >> h2; buf.get();
			buf >> h3; buf.get();
			buf >> h4; buf.get();
			buf >> p1; buf.get();
			buf >> p2;
			
			address pasv_net;
			pasv_net.addr.push_back(h1);
			pasv_net.addr.push_back(h2);
			pasv_net.addr.push_back(h3);
			pasv_net.addr.push_back(h4);
			pasv_net.proto = IP4;
			pasv_net.layer = NETWORK;
		    
			address pasv_port;
			pasv_port.addr.push_back(p1);
			pasv_port.addr.push_back(p2);
			pasv_port.proto = TCP;
			pasv_net.layer = TRANSPORT;

//			std::cerr << "IP: " << pasv_net.to_ip_string()
//				  << std::endl;
//			std::cerr << "Port: " << pasv_port.get_uint16()
//				  << std::endl;

		    }

		    mgr.ftp_response(cp, status, responses);
		    
//		    std::cerr << "Status: " << status << std::endl;
//		    std::cerr << "Response: " << response << std::endl;
//		    std::cerr << std::endl;

		    status_str = "";
		    response = "";
		    responses.clear();
		    state = ftp_server_parser::IN_STATUS;
		    break;
		}
		

		throw exception("FTP server multi-line not implemented");

	    }

	    throw exception("FTP protocol violation: Expect LF");





#ifdef ASDASDSAD






		if (!cont) {

//		    mgr.ftp_response(cp, status, texts);

		    first = true;
		    responses.clear();
		    
		}

		status_str = "";
		response = "";

		state = ftp_server_parser::EXP_FOLLOWUP_LINE;
		break;
	    }

	    throw exception("FTP server protocol violation");

#endif

	default:
	    throw exception("An FTP server parsing state not implemented!");

	}

	s++;

    }

}



#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/ftp.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/event/event_implementations.h>

#include <regex>
#include <iostream>
#include <ctype.h>

using namespace cyberprobe::protocol;


// FTP processing function.
void ftp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    if (c->addr.dest.get_uint16() == 21) {
        ftp::process_client(mgr, c, sl);
        return;
    } else if (c->addr.src.get_uint16() == 21) {
        ftp::process_server(mgr, c, sl);
        return;
    } else {
        throw exception("Trying to handle FTP but neither port number is 21");
    }
}

// FTP client processing function.
void ftp::process_client(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, FTP);
    dest.set(empty, TRANSPORT, FTP);

    flow_address f(src, dest, sl.direc);

    ftp_client_context::ptr fc = ftp_client_context::get_or_create(c, f);

    std::lock_guard<std::mutex> lock(fc->mutex);

    fc->parse(fc, sl, mgr);

}

// FTP server processing function.
void ftp::process_server(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, FTP);
    dest.set(empty, TRANSPORT, FTP);

    flow_address f(src, dest, sl.direc);

    ftp_server_context::ptr fc = ftp_server_context::get_or_create(c, f);

    std::lock_guard<std::mutex> lock(fc->mutex);

    fc->parse(fc, sl, mgr);

}

void ftp_client_parser::parse(context_ptr cp, const pdu_slice& sl,
			      manager& mgr)
{ 

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

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

		static const std::regex 
		    user_cmd(" *USER +(.*)$", std::regex::extended);
		    
		static const std::regex 
		    pass_cmd(" *PASS +(.*)$", std::regex::extended);

		static const std::regex 
		    retr_cmd(" *RETR +(.*)$",
			     std::regex::extended);
		    
		std::match_results<std::string::const_iterator> what;

		if (regex_search(command, what, user_cmd, 
				 std::regex_constants::match_continuous)) {
//		    std::cerr << "User: " << what[1] << std::endl;

		} else if (regex_search(command, what, pass_cmd, 
                                        std::regex_constants::match_continuous)) {
//		    std::cerr << "Password: " << what[1] << std::endl;

		} else if (regex_search(command, what, retr_cmd, 
                                        std::regex_constants::match_continuous)) {
//		    std::cerr << "Retrieve: " << what[1] << std::endl;
//		    context_ptr = as;
		}

		auto ev =
		    std::make_shared<event::ftp_command>(cp, command, sl.time);
		mgr.handle(ev);

/*
  mgr.ftp_command(cp, command);

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
  state = ftp_client_parser::IN_DATA;
  data.clear();
  command = "";
  break;
  }

  if (regex_search(command, what, rset_cmd, 
  std::regex_constants::match_continuous)) {
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


void ftp_server_parser::parse(context_ptr cp, const pdu_slice& sl,
			      manager& mgr)
{ 
    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    while (s != e) {

//	std::cerr << "State: " << state << std::endl;
//	std::cerr << "Char: " << *s << std::endl;

	switch (state) {

	case ftp_server_parser::IN_STATUS:

	    if ((*s >= '0') && (*s <= '9')) {
		status_str += *s;
		break;
	    }

	    if ((*s == ' ') || (*s == '-')) {
		cont = (*s == '-');
		state = ftp_server_parser::IN_TEXT;
		break;

	    }

	    if (*s == '\r') {
		cont = true;
		state = ftp_server_parser::POST_TEXT_EXP_NL;
		break;
	    }

	    if (status_str != "") {
		throw exception("FTP server protocol violation: "
				"Malformed response line");
	    }

	    response += *s;
	    state = ftp_server_parser::IN_TEXT;

	    break;

	case ftp_server_parser::IN_TEXT:

	    if (*s == '\r') {
		state = ftp_server_parser::POST_TEXT_EXP_NL;
		break;
	    }
	    
	    response += *s;
	    break;

	case ftp_server_parser::POST_TEXT_EXP_NL:

	    if (*s != '\n')
		throw exception("FTP server protocol violation: "
				"Expect LF after CR");

	    int s;
	    if (status_str != "") {
		std::istringstream buf(status_str);
		buf >> std::dec >> s;
	    }

//	    std::cerr << "First=" << first << std::endl;
//	    std::cerr << "Cont=" << first << std::endl;
//	    std::cerr << "Response=" << response << std::endl;
//	    std::cerr << "Status_str=" << status_str << std::endl;
//	    std::cerr << "Status=" << status << std::endl;
//	    std::cerr << "S=" << s << std::endl;

	    if (first) {
		if (status_str.length() != 3)
		    throw exception("FTP server protocol violation: "
				    "Malformed status");
		status = s;
		first = false;
	    } else {

		// If status != s, need to 'submit' the current responses,
		// and just deal with this situation. :(
		if ((status_str != "") && (s != status))
		    throw exception("FTP server protocol violation: "
				    "Status mismatch in multi-line response");
		if (status_str == "") cont = true;
	    }

	    responses.push_back(response);

	    static const std::regex 
		passive_cmd("Entering Passive Mode \\(([0-9]+,[0-9]+,[0-9]+"
			    ",[0-9]+,[0-9]+,[0-9]+)\\)",
			    std::regex::extended);
	    
	    {
                std::match_results<std::string::const_iterator> what;
	    
                if (regex_search(responses.front(), what, passive_cmd, 
                                 std::regex_constants::match_continuous)) {

                    std::istringstream buf(what[1]);
		
                    unsigned int h1, h2, h3, h4, p1, p2;
		
                    buf >> std::dec;
                    buf >> h1; buf.get();
                    buf >> h2; buf.get();
                    buf >> h3; buf.get();
                    buf >> h4; buf.get();
                    buf >> p1; buf.get();
                    buf >> p2;
		
                    passive_net.addr.clear();
                    passive_net.addr.push_back(h1);
                    passive_net.addr.push_back(h2);
                    passive_net.addr.push_back(h3);
                    passive_net.addr.push_back(h4);
                    passive_net.proto = IP4;
                    passive_net.layer = NETWORK;
		    
                    passive_port.addr.clear();
                    passive_port.addr.push_back(p1);
                    passive_port.addr.push_back(p2);
                    passive_port.proto = TCP;
                    passive_net.layer = TRANSPORT;

//		std::cerr << "Passive..." << std::endl;
//		std::cerr << "IP: " << passive_net.to_ip_string() << std::endl;
//		std::cerr << "Port: " << passive_port.get_uint16() << std::endl;
		
                }
	    }

	    if (!cont) {
		auto ev =
		    std::make_shared<event::ftp_response>(cp, status, responses,
							  sl.time);
		mgr.handle(ev);
		first = true;
		responses.clear();
	    }
	    
	    status_str = "";
	    response = "";

	    state = ftp_server_parser::IN_STATUS;
	    break;
	    
#ifdef ASDASD
	    if (*s == '\n') {

		responses.push_back(response);
		
		if (!cont) {

		    static const std::regex 
			passive_cmd("Entering Passive Mode \\(([0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+)\\)",
				    std::regex::extended);
		    
		    std::match_results<std::string::const_iterator> what;

		    if (regex_search(response, what, passive_cmd, 
				     std::regex_constants::match_continuous)) {

			std::istringstream buf(what[1]);
			
			unsigned int h1, h2, h3, h4, p1, p2;
			
			buf >> std::dec;
			buf >> h1; buf.get();
			buf >> h2; buf.get();
			buf >> h3; buf.get();
			buf >> h4; buf.get();
			buf >> p1; buf.get();
			buf >> p2;

			passive_net.addr.clear();
			passive_net.addr.push_back(h1);
			passive_net.addr.push_back(h2);
			passive_net.addr.push_back(h3);
			passive_net.addr.push_back(h4);
			passive_net.proto = IP4;
			passive_net.layer = NETWORK;
		    
			passive_port.addr.clear();
			passive_port.addr.push_back(p1);
			passive_port.addr.push_back(p2);
			passive_port.proto = TCP;
			passive_net.layer = TRANSPORT;

#ifdef BROKEN
			context_ptr ftp_data_cp;
//			ftp_data_cp = 

			std::cerr << "IP: " << passive_net.to_ip_string()
				  << std::endl;
			std::cerr << "Port: " << passive_port.get_uint16()
				  << std::endl;

			// FIXME: Assumption - that the sender's IP address
			// is the one that will connect to the FTP data
			// port.

			// From FTP server, get TCP.
			context_ptr par_cp = cp->get_parent();

			// Get IP
			if (par_cp)
			    par_cp = cp->get_parent();

			address net_src, net_dest;

			if (par_cp) {
			    net_src = par_cp->addr.src;
			    net_dest = par_cp->addr.dest;
			}

			// Get IP's parent.
			if (par_cp)
			    par_cp = cp->get_parent();

			flow_address expected_net(net_dest, net_src);

			context_ptr new_cp = 
			    ip4_context::get_or_create(par_cp, expected_net);

			flow_address expected_net(net_dest, net_src);









			
			if (par_cp == 0 || par_cp->get_type() != "tcp")
			    throw exception("Was assuming FTP over TCP");

			par_cp = par_cp->get_parent();

			if (par_cp == 0 || par_cp->get_type() != "ip4")
			    throw exception("Was assuming FTP over IPv4");

			std::cerr << "Looking for data connection "
				  << net_dest.to_ip_string() << " -> "
				  << net_src.to_ip_string() << std::endl;

			flow_address f;
			f.src = net_dest;
			f.dest = net_src;

			par_cp = par_cp->get_parent();

			if (par_cp == 0)
			    throw exception("Expecting IP context to have a "
					    "parent");

			ip_data_cp = par_cp->asd;

#endif
		    }

		    mgr.ftp_response(cp, status, responses);
		    
//		    std::cerr << "Status: " << status << std::endl;
//		    std::cerr << "Response: " << response << std::endl;
//		    std::cerr << std::endl;

		    status_str = "";
		    response = "";
		    responses.clear();

#endif

#ifdef ASDASDASD
		    state = ftp_server_parser::IN_STATUS;
		    break;
		}
		

		throw exception("FTP server multi-line not implemented");

	    }

	    throw exception("FTP protocol violation: Expect LF");

#endif



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


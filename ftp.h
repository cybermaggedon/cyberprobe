
////////////////////////////////////////////////////////////////////////////
//
// FTP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef FTP_H
#define FTP_H

#include <stdint.h>
#include <boost/regex.hpp>

#include <set>

#include "context.h"
#include "manager.h"
#include "serial.h"
#include "protocol.h"

namespace cybermon {

    // FTP client parser.
    class ftp_client_parser {
    public:

    private:

	enum {

	    IN_COMMAND, EXP_NL, IN_DATA

	} state;

    public:

	ftp_client_parser() {
	    state = IN_COMMAND;
	    exp_terminator = "\r\n.\r\n";
	}

	// For the request.
	std::string command;
	std::vector<unsigned char> data;

	std::string terminator;
	std::string exp_terminator;

	std::string from;
	std::list<std::string> to;

	// Parse.
	void parse(context_ptr cp, pdu_iter s, pdu_iter e, manager& mgr);

    };

    // FTP server parser.
    class ftp_server_parser {
    public:

    private:

	enum {

	    IN_STATUS, IN_TEXT, POST_TEXT_EXP_NL,
	    PRE_SUBSEQUENT_LINE, IN_INTERMEDIATE_LINE,
	    IN_LAST_LINE_STATUS, IN_LAST_LINE_TEXT

	} state;

    public:

	ftp_server_parser() {
	    state = IN_STATUS;
	    first = true;
	}

	// For the request.
	bool first;
	int status;
	std::string status_str;
	bool cont;

	std::list<std::string> responses;
	std::string response;

	// Parse.
	void parse(context_ptr cp, pdu_iter s, pdu_iter e, manager& mgr);

    };

    // An FTP client context.
    class ftp_client_context : public context, public ftp_client_parser {
      public:
	
	// Constructor.
        ftp_client_context(manager& m) : 
	context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        ftp_client_context(manager& m, const flow_address& a, 
			    context_ptr p) : 
	context(m) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "ftp_client"; }

	typedef boost::shared_ptr<ftp_client_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new ftp_client_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, ftp_client_context::create);
	    ptr sp = boost::dynamic_pointer_cast<ftp_client_context>(cp);
	    return sp;
	}

    };

    // An FTP server context.
    class ftp_server_context : public context, public ftp_server_parser {
      public:
	
	// Constructor.
        ftp_server_context(manager& m) : 
	context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        ftp_server_context(manager& m, const flow_address& a, 
			    context_ptr p) : 
	context(m) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "ftp_server"; }

	typedef boost::shared_ptr<ftp_server_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new ftp_server_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, ftp_server_context::create);
	    ptr sp = boost::dynamic_pointer_cast<ftp_server_context>(cp);
	    return sp;
	}

    };

    class ftp {

    public:

	// FTP client request processing function.
	static void process_client(manager&, context_ptr c, 
				   pdu_iter s, pdu_iter e);

	// FTP server response processing function.
	static void process_server(manager&, context_ptr c, pdu_iter s, 
				   pdu_iter e);

    };

};

#endif


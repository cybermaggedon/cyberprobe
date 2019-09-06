
////////////////////////////////////////////////////////////////////////////
//
// SMTP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SMTP_H
#define CYBERMON_SMTP_H

#include <stdint.h>

#include <set>

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/util/serial.h>
#include <cyberprobe/analyser/protocol.h>

namespace cyberprobe {
namespace protocol {

    // SMTP client parser.
    class smtp_client_parser {
    public:
        virtual ~smtp_client_parser() {}

    private:

	enum {

	    IN_COMMAND, EXP_NL, IN_DATA

	} state;

    public:

	smtp_client_parser() {
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
	void parse(context_ptr cp, const pdu_slice& sl, manager& mgr);

    };

    // SMTP server parser.
    class smtp_server_parser {
    public:

    private:

	enum {

	    IN_STATUS_CODE, IN_TEXT,
	    EXP_NL

	} state;

    public:

	smtp_server_parser() {
	    state = IN_STATUS_CODE;
	    first = true;
	}

	// For the request.
	std::string status_str;
	int last_status;
	bool first;
	int status;
	bool cont;

	std::list<std::string> texts;
	std::string text;

	// Parse.
	void parse(context_ptr cp, const pdu_slice& sl, manager& mgr);

    };

    // An SMTP client context.
    class smtp_client_context : public context, public smtp_client_parser {
    public:
	
	// Constructor.
        smtp_client_context(manager& m) : 
            context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        smtp_client_context(manager& m, const flow_address& a, 
			    context_ptr p) : 
            context(m) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "smtp_client"; }

	typedef std::shared_ptr<smtp_client_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new smtp_client_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, smtp_client_context::create);
	    ptr sp = std::dynamic_pointer_cast<smtp_client_context>(cp);
	    return sp;
	}

    };

    // An SMTP server context.
    class smtp_server_context : public context, public smtp_server_parser {
    public:
	
	// Constructor.
        smtp_server_context(manager& m) : 
            context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        smtp_server_context(manager& m, const flow_address& a, 
			    context_ptr p) : 
            context(m) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "smtp_server"; }

	typedef std::shared_ptr<smtp_server_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new smtp_server_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, smtp_server_context::create);
	    ptr sp = std::dynamic_pointer_cast<smtp_server_context>(cp);
	    return sp;
	}

    };

    class smtp
    {
    public:

        // SMTP request processing function.
        static void process(manager&, context_ptr c, const pdu_slice& sl);

    private:

        using manager = cyberprobe::analyser::manager;

        // SMTP client request processing function.
        static void process_client(manager&, context_ptr c,
                                   const pdu_slice& sl);

        // SMTP server response processing function.
        static void process_server(manager&, context_ptr c,
                                   const pdu_slice& sl);
    };

}
}

#endif


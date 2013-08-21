
////////////////////////////////////////////////////////////////////////////
//
// DNS processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef DNS_H
#define DNS_H

#include <stdint.h>

#include <set>

#include "context.h"
#include "manager.h"
#include "serial.h"
#include "protocol.h"

namespace analyser {

    enum dns_rcode_t {
	NO_ERROR = 0,
	FORMAT_ERROR = 1,
	SERVER_FAILURE = 2,
	NAME_ERROR = 3,
	NOT_IMPLEMENTED = 4,
	REFUED = 5
    };

    enum dns_type_t {
	A = 1,
	NS = 2,
	MD = 3,
	MF = 4,
	CNAME = 5,
	SOA = 6,
	EXP_MB = 7,
	EXP_MG = 8,
	EX_MR = 9,
	EXP_NULL = 10,
	WKS = 11,
	PTR = 12,
	HINFO = 13,
	MINFO = 14,
	MX = 15,
	TXT = 16,
	AAAA = 28
    };

    enum dns_cls_t {
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4
    };

    enum dns_opcode_t {
	QUERY = 0,
	IQUERY = 1,
	STATUS = 2
    };

    class dns_header {
    public:

	uint16_t id;
	uint8_t qr;
	uint8_t opcode;
	uint8_t aa;
	uint8_t tc;
	uint8_t rd;
	uint8_t ra;
	uint8_t rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
    };

    class dns_query {
    public:
	std::string name;
	uint16_t type;
	uint16_t cls;
    };

    class dns_rr {
    public:
	std::string name;
	uint16_t type;
	uint16_t cls;
	uint16_t rdlength;
	pdu rdata;
	uint32_t ttl;

	std::string rdname;
	address addr;

    };

    class dns_decoder {
	pdu_iter s;
	pdu_iter e;
	pdu_iter ptr;

    public:

	dns_header hdr;
	std::list<dns_query> queries;
	std::list<dns_rr> answers;
	std::list<dns_rr> authorities;
	std::list<dns_rr> additional;

	dns_decoder(pdu_iter s, pdu_iter e) {
	    this->s = s; this->e = e;
	}
	void parse();
	void parse_header();
	void parse_name(pdu_iter ms, pdu_iter me, 
			pdu_iter& pos, pdu_iter e, std::string&,
			bool& first);
	void parse_queries();
	void parse_rrs(std::list<dns_rr>& rrs, int n);
	void parse_rr(dns_rr& r);
    };

    // A DNS context.
    class dns_context : public context {
      public:
	
	// Constructor.
        dns_context(manager& m) : context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        dns_context(manager& m, const flow& a, context_ptr p) : context(m) { 
	    addr = a; parent = p; 
	}

	// Type is "dns".
	virtual std::string get_type() { return "dns"; }

	typedef boost::shared_ptr<dns_context> ptr;

	static context_ptr create(manager& m, const flow& f, context_ptr par) {
	    context_ptr cp = context_ptr(new dns_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow& f) {
	    context_ptr cp = context::get_or_create(base, f, 
						    dns_context::create);
	    ptr sp = boost::dynamic_pointer_cast<dns_context>(cp);
	    return sp;
	}

    };

    class dns {

      public:

	// DNS processing function.
	static void process(manager&, context_ptr c, pdu_iter s, pdu_iter e);

    };

};

#endif


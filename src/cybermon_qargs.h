/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 qargs. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.


 ****************************************************************************/

#ifndef CYBERMON_QARGS_H_
#define CYBERMON_QARGS_H_

#include <cybermon/engine.h>

/*
 * args classes for different protocols
 */
class qargs {

public:
	//Constructor
	qargs() {
	}
	;
	//Destructor
	virtual ~qargs() {
	}
	;

};

class connection_args: public qargs {

public:
	connection_args(const cybermon::context_ptr cp) :
			cptr(cp) {
	}
	cybermon::context_ptr cptr;

};

class trigger_up_args: public qargs {

public:
	trigger_up_args(const std::string& liid, const std::string& a) :
			trupliid(liid), trupaddr(a) {
	}
	std::string trupliid;
	const std::string trupaddr;

};

class trigger_down_args: public qargs {

public:
	trigger_down_args(const std::string& liid) :
			trdownliid(liid) {
	}
	std::string trdownliid;

};

class unrecognised_stream_args: public qargs {

public:
	unrecognised_stream_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;
};

class unrecognised_datagram_args: public qargs {

public:
	unrecognised_datagram_args(const cybermon::context_ptr cp,
			cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;
};

class icmp_args: public qargs {

public:
	icmp_args(const cybermon::context_ptr cp, unsigned int type,
			unsigned int code, cybermon::pdu data) :
			cptr(cp), icmptype(type), icmpcode(code), icmpdata(data) {
	}
	cybermon::context_ptr cptr;
	unsigned int icmptype;
	unsigned int icmpcode;
	cybermon::pdu icmpdata;

};

class imap_args: public qargs {

public:
	imap_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;
};

class imap_ssl_args: public qargs {

public:
	imap_ssl_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;

};

class pop3_args: public qargs {

public:
	pop3_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;
};

class pop3_ssl_args: public qargs {

public:
	pop3_ssl_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;

};

class rtp_args: public qargs {

public:
	rtp_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;
};

class rtp_ssl_args: public qargs {

public:
	rtp_ssl_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;

};

class smtp_auth_args: public qargs {

public:
	smtp_auth_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;

};

class sip_ssl_args: public qargs {

public:
	sip_ssl_args(const cybermon::context_ptr cp, cybermon::pdu data) :
			cptr(cp), pdu(data) {
	}
	cybermon::context_ptr cptr;
	cybermon::pdu pdu;

};

class sip_request_args: public qargs {

public:
	sip_request_args(const cybermon::context_ptr cp, const std::string& method,
			const std::string& from, const std::string& to, cybermon::pdu data) :
			cptr(cp), sipmethod(method), sipfrom(from), sipto(to), pdu(data) {
	}
	cybermon::context_ptr cptr;
	const std::string sipmethod;
	const std::string sipfrom;
	const std::string sipto;
	cybermon::pdu pdu;

};

class sip_response_args: public qargs {

public:
	sip_response_args(const cybermon::context_ptr cp, unsigned int code,
			const std::string& status, const std::string& from,
			const std::string& to, cybermon::pdu data) :
			cptr(cp), sipcode(code), sipstatus(status), sipfrom(from), sipto(
					to), pdu(data) {
	}
	cybermon::context_ptr cptr;
	unsigned int sipcode;
	const std::string sipstatus;
	const std::string sipfrom;
	const std::string sipto;
	cybermon::pdu pdu;

};

class http_request_args: public qargs {

public:
	http_request_args(const cybermon::context_ptr cp, const std::string& method,
			const std::string& url, const cybermon::observer::http_hdr_t& hdr,
			cybermon::pdu data) :
			cptr(cp), httpmethod(method), httpurl(url), httphdr(hdr), pdu(data) {
	}
	cybermon::context_ptr cptr;
	const std::string httpmethod;
	const std::string httpurl;
	cybermon::observer::http_hdr_t httphdr;
	cybermon::pdu pdu;
};

class http_response_args: public qargs {

public:
	http_response_args(const cybermon::context_ptr cp, unsigned int code,
			const std::string& status,
			const cybermon::observer::http_hdr_t& hdr, const std::string& url,
			cybermon::pdu data) :
			cptr(cp), httpcode(code), httpstatus(status), httphdr(hdr), httpurl(
					url), pdu(data) {
	}
	cybermon::context_ptr cptr;
	unsigned int httpcode;
	const std::string httpstatus;
	cybermon::observer::http_hdr_t httphdr;
	const std::string httpurl;
	cybermon::pdu pdu;
};

class smtp_command_args: public qargs {

public:
	smtp_command_args(const cybermon::context_ptr cp,
			const std::string& command) :
			cptr(cp), smtpcommand(command) {
	}
	cybermon::context_ptr cptr;
	const std::string smtpcommand;

};

class smtp_response_args: public qargs {

public:
	smtp_response_args(const cybermon::context_ptr cp, int status,
			const std::list<std::string>& text) :
			cptr(cp), smtpstatus(status), smtptext(text) {
	}
	cybermon::context_ptr cptr;
	int smtpstatus;
	const std::list<std::string> smtptext;

};

class smtp_data_args: public qargs {

public:
	smtp_data_args(const cybermon::context_ptr cp, const std::string& from,
			const std::list<std::string>& to,
			std::vector<unsigned char>::const_iterator s,
			std::vector<unsigned char>::const_iterator e) :
			cptr(cp), smtpfrom(from), smtpto(to), smtps(s), smtpe(e) {
	}
	cybermon::context_ptr cptr;
	const std::string smtpfrom;
	const std::list<std::string> smtpto;
	std::vector<unsigned char>::const_iterator smtps;
	std::vector<unsigned char>::const_iterator smtpe;

};

class ftp_command_args: public qargs {

public:
	ftp_command_args(const cybermon::context_ptr cp, const std::string& command) :
			cptr(cp), ftpcommand(command) {
	}
	cybermon::context_ptr cptr;
	const std::string ftpcommand;

};

class ftp_response_args: public qargs {

public:
	ftp_response_args(const cybermon::context_ptr cp, int status,
			const std::list<std::string>& responses) :
			cptr(cp), ftpstatus(status), ftpresponses(responses) {
	}
	cybermon::context_ptr cptr;
	int ftpstatus;
	const std::list<std::string> ftpresponses;

};

class dns_message_args: public qargs {

public:
	dns_message_args(const cybermon::context_ptr cp,
			const cybermon::dns_header hdr,
			const std::list<cybermon::dns_query> queries,
			const std::list<cybermon::dns_rr> answers,
			const std::list<cybermon::dns_rr> authorities,
			const std::list<cybermon::dns_rr> additional) :
			cptr(cp), dnshdr(hdr), dnsqueries(queries), dnsanswers(answers), dnsauthorities(
					authorities), dnsadditional(additional) {

	}
	cybermon::context_ptr cptr;
	cybermon::dns_header dnshdr;
	std::list<cybermon::dns_query> dnsqueries;
	std::list<cybermon::dns_rr> dnsanswers;
	std::list<cybermon::dns_rr> dnsauthorities;
	std::list<cybermon::dns_rr> dnsadditional;

};

class ntp_timestamp_message_args: public qargs {

public:
	ntp_timestamp_message_args(const cybermon::context_ptr cp,
			const cybermon::ntp_timestamp& ts) :
			cptr(cp), ntpts(ts) {
	}
	cybermon::context_ptr cptr;
	const cybermon::ntp_timestamp ntpts;

};

class ntp_control_message_args: public qargs {

public:
	ntp_control_message_args(const cybermon::context_ptr cp,
			const cybermon::ntp_control& ctrl) :
			cptr(cp), ntpctrl(ctrl) {
	}
	cybermon::context_ptr cptr;
	const cybermon::ntp_control ntpctrl;

};

class ntp_private_message_args: public qargs {

public:
	ntp_private_message_args(const cybermon::context_ptr cp,
			const cybermon::ntp_private& priv) :
			cptr(cp), ntppriv(priv) {
	}
	cybermon::context_ptr cptr;
	const cybermon::ntp_private ntppriv;

};

//enum to use in cybermon_qreader to find out which cybermon lua function to call
enum call_type {
	connection_up,
	connection_down,
	trigger_up,
	trigger_down,
	unrecognised_stream,
	unrecognised_datagram,
	icmp,
	imap,
	imap_ssl,
	pop3,
	pop3_ssl,
	rtp,
	rtp_ssl,

	sip_request,
	sip_response,
	sip_ssl,
	smtp_auth,
	smtp_command,
	smtp_response,
	smtp_data,
	http_request,
	http_response,
	ftp_command,
	ftp_response,
	dns_message,
	ntp_timestamp_message,
	ntp_control_message,
	ntp_private_message

};

/*q_entry class acting as a medium to store args and add in to queue by cybermon_qwriter
 * and cybermon_qreader pick up it from queue to process by calling
 * cybermon lua bridge
 */
class q_entry {

public:
	//Constructor
	q_entry(call_type call, qargs* args) :
			calltype(call), queueargs(args) {
	}

	//Constructor
	q_entry(const q_entry &obj) {

		queueargs = obj.queueargs;
		calltype = obj.calltype;
	}

	q_entry& operator=(const q_entry &obj) {
		if (this != &obj) {

			queueargs = obj.queueargs;
			calltype = obj.calltype;
		}
		return *this;
	}

	//Destructor
	virtual ~q_entry() {
	}
	;

	qargs* queueargs;
	call_type calltype;

};
#endif /* CYBERMON_QARGS_H_ */

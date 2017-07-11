/*
 * cybermon_qwriter.h
 *
 *  Created on: 21 Jun 2017
 *      Author: venkata
 */


#ifndef CYBERMON_QWRITER_H_
#define CYBERMON_QWRITER_H_

#include <cybermon/cybermon-lua.h>
#include <cybermon/engine.h>
#include <queue>
#include<cybermon_qargs.h>

class cybermon_qwriter : public cybermon::engine{

public:
	//Constructor
	cybermon_qwriter(const std::string& path, std::queue<q_entry*>& cybermonq, threads::mutex& cqwrlock);
	//Destructor.
	virtual ~cybermon_qwriter() {}

	int writecount;

	std::queue<q_entry*>&	cqueue;

	threads::mutex& lock;

	virtual void connection_up(const cybermon::context_ptr cp);
	virtual void connection_down(const cybermon::context_ptr cp);

	virtual void sip_ssl(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);

	virtual void smtp_auth(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);

	virtual void rtp_ssl(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);
	virtual void rtp(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);
	virtual void pop3_ssl(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);
	virtual void pop3(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);
	virtual void imap_ssl(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);

	virtual void imap(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);
	virtual void icmp(const cybermon::context_ptr cp,
			unsigned int type,
			unsigned int code,
			cybermon::pdu_iter s,
			cybermon::pdu_iter e);
	virtual void sip_request(const cybermon::context_ptr cp,
			const std::string& method,
			const std::string& from,
			const std::string& to,
			cybermon::pdu_iter s,
			cybermon::pdu_iter e);
	virtual void sip_response(const cybermon::context_ptr cp,
			unsigned int code,
			const std::string& status,
			const std::string& from,
			const std::string& to,
			cybermon::pdu_iter s,
			cybermon::pdu_iter e);
	virtual void http_request(const cybermon::context_ptr cp,
			const std::string& method,
			const std::string& url,
			const cybermon::observer::http_hdr_t& hdr,
			cybermon::pdu_iter body_start,
			cybermon::pdu_iter body_end);
	virtual void http_response(const cybermon::context_ptr cp,
			unsigned int code,
			const std::string& status,
			const cybermon::observer::http_hdr_t& hdr,
			const std::string& url,
			cybermon::pdu_iter body_start,
			cybermon::pdu_iter body_end);
	virtual void smtp_command(const cybermon::context_ptr cp,
			const std::string& command);

	virtual void smtp_response(const cybermon::context_ptr cp,
			int status,
			const std::list<std::string>& text);

	virtual void smtp_data(const cybermon::context_ptr cp,
			const std::string& from,
			const std::list<std::string>& to,
			std::vector<unsigned char>::const_iterator s,
			std::vector<unsigned char>::const_iterator e) ;

	virtual void ftp_command(const cybermon::context_ptr cp,
			const std::string& command) ;
	virtual void ftp_response(const cybermon::context_ptr cp,
			int status,
			const std::list<std::string>& responses);
	//void trigger_up(const std::string& liid, const tcpip::address& a);
	void trigger_up(const std::string& liid, const tcpip::address& a);
	void trigger_down(const std::string& liid);
	virtual void dns_message(const cybermon::context_ptr cp,
			const cybermon::dns_header hdr,
			const std::list<cybermon::dns_query> queries,
			const std::list<cybermon::dns_rr> answers,
			const std::list<cybermon::dns_rr> authorities,
			const std::list<cybermon::dns_rr> additional);
	virtual void ntp_timestamp_message(const cybermon::context_ptr cp,
			const cybermon::ntp_timestamp& ts);
	virtual void ntp_control_message(const cybermon::context_ptr cp,
			const cybermon::ntp_control& ctrl);
	virtual void ntp_private_message(const cybermon::context_ptr cp,
			const cybermon::ntp_private& priv);
	virtual void unrecognised_stream(const cybermon::context_ptr cp,
			cybermon::pdu_iter s,
			cybermon::pdu_iter e);
	virtual void unrecognised_datagram(const cybermon::context_ptr cp,
			cybermon::pdu_iter s, cybermon::pdu_iter e);
	virtual void close();
};






#endif /* CYBERMON_QWRITER_H_ */

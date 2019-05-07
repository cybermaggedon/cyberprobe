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
#include <cybermon_qargs.h>
#include <cybermon/tls_handshake_protocol.h>

#include <queue>
#include <vector>

namespace cybermon {

    class cybermon_qwriter: public engine {

      public:

	// Constructor
        cybermon_qwriter(const std::string& path,
			 std::queue<q_entry*>& cybermonq,
			 threads::mutex& cqwrlock);
	// Destructor.
	virtual ~cybermon_qwriter() {
	}

	std::queue<q_entry*>& cqueue;

	threads::mutex& lock;

	virtual void connection_up(const context_ptr cp,
				   const pdu_time& tv);

	virtual void connection_down(const context_ptr cp,
				     const pdu_time& tv);

	virtual void sip_ssl(const context_ptr cp, pdu_iter s, pdu_iter e,
			     const pdu_time& tv);

	virtual void smtp_auth(const context_ptr cp, pdu_iter s, pdu_iter e,
			       const pdu_time& tv);

	virtual void rtp_ssl(const context_ptr cp,
			     const pdu_iter s, pdu_iter e,
			     const pdu_time& tv);

	virtual void rtp(const context_ptr cp, pdu_iter s, pdu_iter e,
			 const pdu_time& tv);

	virtual void pop3_ssl(const context_ptr cp, pdu_iter s, pdu_iter e,
			      const pdu_time& tv);

	virtual void pop3(const context_ptr cp, pdu_iter s, pdu_iter e,
			  const pdu_time& tv);

	virtual void imap_ssl(const context_ptr cp, pdu_iter s, pdu_iter e,
			      const pdu_time& tv);

	virtual void imap(const context_ptr cp, pdu_iter s, pdu_iter e,
			  const pdu_time& tv);

	virtual void icmp(const context_ptr cp, unsigned int type,
			  unsigned int code, pdu_iter s, pdu_iter e,
			  const pdu_time& tv);

	virtual void sip_request(const context_ptr cp,
				 const std::string& method,
				 const std::string& from,
				 const std::string& to,
				 pdu_iter s, pdu_iter e,
				 const pdu_time& tv);

	virtual void sip_response(const context_ptr cp, unsigned int code,
				  const std::string& status,
				  const std::string& from,
				  const std::string& to,
				  pdu_iter s, pdu_iter e,
				  const pdu_time& tv);

	virtual void http_request(const context_ptr cp,
				  const std::string& method,
				  const std::string& url,
				  const observer::http_hdr_t& hdr,
				  pdu_iter body_start, pdu_iter body_end,
				  const pdu_time& tv);
	
	virtual void http_response(const context_ptr cp,
				   unsigned int code,
				   const std::string& status,
				   const observer::http_hdr_t& hdr,
				   const std::string& url,
				   pdu_iter body_start, pdu_iter body_end,
				   const pdu_time& tv);

	virtual void smtp_command(const context_ptr cp,
				  const std::string& command,
				  const pdu_time& tv);
	virtual void smtp_response(const context_ptr cp, int status,
				   const std::list<std::string>& text,
				   const pdu_time& tv);
	virtual void smtp_data(const context_ptr cp,
			       const std::string& from,
			       const std::list<std::string>& to,
			       std::vector<unsigned char>::const_iterator s,
			       std::vector<unsigned char>::const_iterator e,
			       const pdu_time& tv);

	virtual void ftp_command(const context_ptr cp,
				 const std::string& command,
				 const pdu_time& tv);
	virtual void ftp_response(const context_ptr cp, int status,
				  const std::list<std::string>& responses,
				  const pdu_time& tv);

	void trigger_up(const std::string& liid, const tcpip::address& a,
			const pdu_time& tv);

	void trigger_down(const std::string& liid, const pdu_time& tv);

	virtual void dns_message(const context_ptr cp,
				 const dns_header hdr,
				 const std::list<dns_query> queries,
				 const std::list<dns_rr> answers,
				 const std::list<dns_rr> authorities,
				 const std::list<dns_rr> additional,
				 const pdu_time& tv);

	virtual void ntp_timestamp_message(const context_ptr cp,
					   const ntp_timestamp& ts,
					   const pdu_time& tv);
	virtual void ntp_control_message(const context_ptr cp,
					 const ntp_control& ctrl,
					 const pdu_time& tv);
	virtual void ntp_private_message(const context_ptr cp,
					 const ntp_private& priv,
					 const pdu_time& tv);

	virtual void unrecognised_stream(const context_ptr cp,
					 pdu_iter s, pdu_iter e,
					 const pdu_time& tv,
                                         int64_t posn);
	virtual void unrecognised_datagram(const context_ptr cp,
					   pdu_iter s, pdu_iter e,
					   const pdu_time& tv);
	virtual void close();

	virtual void gre(const context_ptr cp,
				     const std::string& nxt_proto,
 				     const uint32_t key,
 				     const uint32_t seq,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv);

	virtual void gre_pptp(const context_ptr cp,
				     const std::string& nxt_proto,
 				     const uint16_t payload_length,
 				     const uint16_t call_id,
 				     const uint32_t sequenceNo,
 				     const uint32_t ackNo,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv);

	virtual void esp(const context_ptr cp,
 				     const uint32_t spi,
 				     const uint32_t sequence,
 				     const uint32_t length,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv);

	virtual void unrecognised_ip_protocol(const context_ptr cp,
 				     const uint8_t nxtProto,
 				     const uint32_t len,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv);

	virtual void wlan(const context_ptr cp,
 				     const uint8_t version,
 				     const uint8_t type,
 				     const uint8_t subtype,
 				     const uint8_t flags,
 				     const bool is_protected,
 				     const uint16_t duration,
 				     const std::string& filt_addr,
 				     const uint8_t frag_num,
 				     const uint16_t seq_num,
 				     const timeval& tv);

	virtual void tls(const context_ptr cp,
             const std::string& version,
             const uint8_t contentType,
             const uint16_t length,
             const timeval& tv);

	virtual void tls_client_hello(const context_ptr cp,
             const tls_handshake_protocol::client_hello_data& data,
             const timeval& tv);

	virtual void tls_server_hello(const context_ptr cp,
             const tls_handshake_protocol::server_hello_data& data,
             const timeval& tv);

	virtual void tls_certificates(const context_ptr cp,
              const std::vector<std::vector<uint8_t>>& certs,
              const timeval& tv);

	// Max size of queue.
	static const int q_limit = 1000;

	virtual void push(q_entry* e) {
	    lock.lock();

	    // Sleep until queue is below the queue limit.
	    while (cqueue.size() >= q_limit) {
		lock.unlock();
		usleep(10);
		lock.lock();
	    }

	    cqueue.push(e);
	    lock.unlock();
	}

    };

};

#endif /* CYBERMON_QWRITER_H_ */

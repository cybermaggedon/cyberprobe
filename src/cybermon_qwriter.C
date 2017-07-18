/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 cybermon_qwriter. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.
 Creates args for different protocols and put in to q_entry to add in to a queue

 ****************************************************************************/

#include <cybermon_qwriter.h>
#include <cybermon_qargs.h>

#include <iostream>
#include <iomanip>
#include <map>

#include <boost/program_options.hpp>

#include <cybermon/engine.h>
#include <cybermon/monitor.h>
#include <cybermon/etsi_li.h>
#include <cybermon/packet_capture.h>
#include <cybermon/context.h>
#include <cybermon/cybermon-lua.h>

cybermon_qwriter::cybermon_qwriter(const std::string& path,
		std::queue<q_entry*>& cybermonq, threads::mutex& cqwrlock) :
		cqueue(cybermonq), lock(cqwrlock) {
}

// Connection-orientated.
void cybermon_qwriter::connection_up(const cybermon::context_ptr cp) {
	try {
		qargs* args = new connection_args(cp);
		q_entry* qentry = new q_entry(qargs::connection_up, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::connection_down(const cybermon::context_ptr cp) {
	try {
		qargs* args = new connection_args(cp);
		q_entry* qentry = new q_entry(qargs::connection_down, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// Trigger
void cybermon_qwriter::trigger_up(const std::string& liid,
		const tcpip::address& a) {
	try {
		std::string addr;
		a.to_string(addr);
		qargs* args = new trigger_up_args(liid, addr);
		q_entry* qentry = new q_entry(qargs::trigger_up, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::trigger_down(const std::string& liid) {
	try {
		qargs* args = new trigger_down_args(liid);
		q_entry* qentry = new q_entry(qargs::trigger_down, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::unrecognised_stream(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new unrecognised_stream_args(cp, data);
		q_entry* qentry = new q_entry(qargs::unrecognised_stream, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// Connection-less
void cybermon_qwriter::unrecognised_datagram(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {

		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new unrecognised_datagram_args(cp, data);
		q_entry* qentry = new q_entry(qargs::unrecognised_datagram, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::icmp(const cybermon::context_ptr cp, unsigned int type,
		unsigned int code, cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new icmp_args(cp, type, code, data);
		q_entry* qentry = new q_entry(qargs::icmp, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::imap(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new imap_args(cp, data);
		q_entry* qentry = new q_entry(qargs::imap, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::imap_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new imap_ssl_args(cp, data);
		q_entry* qentry = new q_entry(qargs::imap_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::pop3(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new pop3_args(cp, data);
		q_entry* qentry = new q_entry(qargs::pop3, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::pop3_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new pop3_ssl_args(cp, data);
		q_entry* qentry = new q_entry(qargs::pop3_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::rtp(const cybermon::context_ptr cp, cybermon::pdu_iter s,
		cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new rtp_args(cp, data);
		q_entry* qentry = new q_entry(qargs::rtp, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::rtp_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new rtp_ssl_args(cp, data);
		q_entry* qentry = new q_entry(qargs::rtp_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::smtp_auth(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new smtp_auth_args(cp, data);
		q_entry* qentry = new q_entry(qargs::smtp_auth, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::sip_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new sip_ssl_args(cp, data);
		q_entry* qentry = new q_entry(qargs::sip_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}
void cybermon_qwriter::sip_request(const cybermon::context_ptr cp,
		const std::string& method, const std::string& from,
		const std::string& to, cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new sip_request_args(cp, method, from, to, data);
		q_entry* qentry = new q_entry(qargs::sip_request, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::sip_response(const cybermon::context_ptr cp,
		unsigned int code, const std::string& status, const std::string& from,
		const std::string& to, cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new sip_response_args(cp, code, status, from, to, data);
		q_entry* qentry = new q_entry(qargs::sip_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// HTTP
void cybermon_qwriter::http_request(const cybermon::context_ptr cp,
		const std::string& method, const std::string& url,
		const cybermon::observer::http_hdr_t& hdr, cybermon::pdu_iter s,
		cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new http_request_args(cp, method, url, hdr, data);
		q_entry* qentry = new q_entry(qargs::http_request, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::http_response(const cybermon::context_ptr cp,
		unsigned int code, const std::string& status,
		const cybermon::observer::http_hdr_t& hdr, const std::string& url,
		cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
		cybermon::pdu data(e - s);
		memcpy(&data[0], &(*s), e - s);

		qargs* args = new http_response_args(cp, code, status, hdr, url, data);
		q_entry* qentry = new q_entry(qargs::http_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// SMTP
void cybermon_qwriter::smtp_command(const cybermon::context_ptr cp,
		const std::string& command) {
	try {
		qargs* args = new smtp_command_args(cp, command);
		q_entry* qentry = new q_entry(qargs::smtp_command, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::smtp_response(const cybermon::context_ptr cp, int status,
		const std::list<std::string>& text) {
	try {
		qargs* args = new smtp_response_args(cp, status, text);
		q_entry* qentry = new q_entry(qargs::smtp_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::smtp_data(const cybermon::context_ptr cp,
		const std::string& from, const std::list<std::string>& to,
		std::vector<unsigned char>::const_iterator s,
		std::vector<unsigned char>::const_iterator e) {
	try {
		qargs* args = new smtp_data_args(cp, from, to, s, e);
		q_entry* qentry = new q_entry(qargs::smtp_data, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// FTP
void cybermon_qwriter::ftp_command(const cybermon::context_ptr cp,
		const std::string& command) {
	try {
		qargs* args = new ftp_command_args(cp, command);
		q_entry* qentry = new q_entry(qargs::ftp_command, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::ftp_response(const cybermon::context_ptr cp, int status,
		const std::list<std::string>& responses) {
	try {
		qargs* args = new ftp_response_args(cp, status, responses);
		q_entry* qentry = new q_entry(qargs::ftp_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// DNS
void cybermon_qwriter::dns_message(const cybermon::context_ptr cp,
		const cybermon::dns_header hdr,
		const std::list<cybermon::dns_query> queries,
		const std::list<cybermon::dns_rr> answers,
		const std::list<cybermon::dns_rr> authorities,
		const std::list<cybermon::dns_rr> additional) {
	try {

		qargs* args = new dns_message_args(cp, hdr, queries, answers,
				authorities, additional);
		q_entry* qentry = new q_entry(qargs::dns_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// NTP
void cybermon_qwriter::ntp_timestamp_message(const cybermon::context_ptr cp,
		const cybermon::ntp_timestamp& ts) {
	try {
		qargs* args = new ntp_timestamp_message_args(cp, ts);
		q_entry* qentry = new q_entry(qargs::ntp_timestamp_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::ntp_control_message(const cybermon::context_ptr cp,
		const cybermon::ntp_control& ctrl) {
	try {
		qargs* args = new ntp_control_message_args(cp, ctrl);
		q_entry* qentry = new q_entry(qargs::ntp_control_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::ntp_private_message(const cybermon::context_ptr cp,
		const cybermon::ntp_private& priv) {
	try {
		qargs* args = new ntp_private_message_args(cp, priv);
		q_entry* qentry = new q_entry(qargs::ntp_private_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

}
//to signal cybermon_qreader to stop
void cybermon_qwriter::close() {
	q_entry* qentry = NULL;
	lock.lock();
	cqueue.push(qentry);
	lock.unlock();
}


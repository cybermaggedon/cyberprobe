
/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

Simple monitor.  Takes ETSI streams from cyberprobe, and reports on various
occurances.

Usage:

    cyberprobe <port-number>

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

cybermon_qwriter::cybermon_qwriter(const std::string& path, std::queue<q_entry*>& cybermonq, threads::mutex& cqwrlock) :  cqueue(cybermonq), lock(cqwrlock), writecount(0) {}


// Connection-orientated.
void cybermon_qwriter::connection_up(const cybermon::context_ptr cp) {
	try {
		//std::cout<<"called cybermon_qwriter connection_up";
		//cml.connection_up(*this, cp);
		qargs* args = new connection_args(cp);
		q_entry* qentry = new q_entry(call_type::connection_up, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::connection_down(const cybermon::context_ptr cp) {
	try{
		//std::cout<<"called cybermon_qwriter connection_down";
		//cml.connection_down(*this, cp);
		qargs* args = new connection_args(cp);
		q_entry* qentry = new q_entry(call_type::connection_down, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// Trigger
void cybermon_qwriter::trigger_up(const std::string& liid, const tcpip::address& a) {
	try {
		std::cout<<"called cybermon_qwriter trigger_up:"<< a;
		//cml.trigger_up(liid, a);

		std::string addr;
		a.to_string(addr);
		qargs* args = new trigger_up_args(liid, addr);
		q_entry* qentry = new q_entry(call_type::trigger_up, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();


	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::trigger_down(const std::string& liid) {
	try {
		//std::cout<<"called cybermon_qwriter trigger_down";
		//cml.trigger_down(liid);
		qargs* args = new trigger_down_args(liid);
		q_entry* qentry = new q_entry(call_type::trigger_down, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}



void cybermon_qwriter::unrecognised_stream(const cybermon::context_ptr cp,
		cybermon::pdu_iter s,
		cybermon::pdu_iter e) {
	try {
		// cml.unrecognised_stream(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter unrecognised_stream::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);

		//qargs* args = new unrecognised_stream_args(cp,s,e);
		qargs* args = new unrecognised_stream_args(cp,data);
		q_entry* qentry = new q_entry(call_type::unrecognised_stream, args);
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
		//cml.unrecognised_datagram(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter unrecognised_datagram::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new unrecognised_datagram_args(cp,data);
		//qargs* args = new unrecognised_datagram_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::unrecognised_datagram, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::icmp(const cybermon::context_ptr cp,
		unsigned int type,
		unsigned int code,
		cybermon::pdu_iter s,
		cybermon::pdu_iter e) {
	try {
		//cml.icmp(*this, cp, type, code, s, e);
		writecount++;
		//std::cout<<"calling cybermon_qwriter icmp::   "<<" write count:"<<writecount<<std::endl;
		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new icmp_args(cp,type,code,data);
		//qargs* args = new icmp_args(cp,type,code,s,e);
		q_entry* qentry = new q_entry(call_type::icmp, args);
		lock.lock();
		/*std::cerr << "cybermon_qwriter::icmp::";

		for (cybermon::pdu_iter i = s; i != e ; ++i)
			std::cerr<< std::setw(2)<<std::setfill('0')<<std::hex << static_cast<uint16_t> (*i) ;

		std::cerr<<std::endl;*/

		cqueue.push(qentry);
		//delete(qentry);
		lock.unlock();
	}
	catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::imap(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.imap(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter imap::   "<<" write count:"<<writecount<<std::endl;
		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new imap_args(cp,data);

		//qargs* args = new imap_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::imap, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::imap_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.imap_ssl(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter imap_ssl::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);

		qargs* args = new imap_ssl_args(cp,data);
		//qargs* args = new imap_ssl_args(cp,s,e);

		q_entry* qentry = new q_entry(call_type::imap_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}


void cybermon_qwriter::pop3(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.pop3(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter pop3::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new pop3_args(cp,data);

		//qargs* args = new pop3_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::pop3, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}


void cybermon_qwriter::pop3_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.pop3_ssl(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter pop3_ssl::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new pop3_ssl_args(cp,data);

		//qargs* args = new pop3_ssl_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::pop3_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::rtp(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.rtp(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter rtp::   "<<" write count:"<<writecount<<std::endl;


		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new rtp_args(cp,data);


		//qargs* args = new rtp_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::rtp, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}


void cybermon_qwriter::rtp_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.rtp_ssl(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter rtp_ssl::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new rtp_ssl_args(cp,data);

		//qargs* args = new rtp_ssl_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::rtp_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::smtp_auth(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.smtp_auth(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter smtp_auth::   "<<" write count:"<<writecount<<std::endl;


		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new smtp_auth_args(cp,data);

		//qargs* args = new smtp_auth_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::smtp_auth, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::sip_ssl(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e)
{
	try
	{
		//cml.sip_ssl(*this, cp, s, e);
		//std::cout<<"calling cybermon_qwriter sip_ssl::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new sip_ssl_args(cp,data);

		//qargs* args = new sip_ssl_args(cp,s,e);
		q_entry* qentry = new q_entry(call_type::sip_ssl, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}
void cybermon_qwriter::sip_request(const cybermon::context_ptr cp,
		const std::string& method,
		const std::string& from,
		const std::string& to,
		cybermon::pdu_iter s,
		cybermon::pdu_iter e)
{
	try
	{
		//cml.sip_request(*this, cp, method, from, to, s, e);
		//std::cout<<"calling cybermon_qwriter sip_request::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);

		qargs* args = new sip_request_args(cp, method, from, to, data);
		//qargs* args = new sip_request_args(cp, method, from, to, s,e);
		q_entry* qentry = new q_entry(call_type::sip_request, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::sip_response(const cybermon::context_ptr cp,
		unsigned int code,
		const std::string& status,
		const std::string& from,
		const std::string& to,
		cybermon::pdu_iter s,
		cybermon::pdu_iter e)
{
	try
	{
		//cml.sip_response(*this, cp, code, status, from, to, s, e);
		//std::cout<<"calling cybermon_qwriter sip_response::   "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new sip_response_args(cp, code, status, from, to, data);

		//qargs* args = new sip_response_args(cp, code, status, from, to, s,e);
		q_entry* qentry = new q_entry(call_type::sip_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// HTTP
void cybermon_qwriter::http_request(const cybermon::context_ptr cp,
		const std::string& method,
		const std::string& url,
		const cybermon::observer::http_hdr_t& hdr,
		cybermon::pdu_iter s,
		cybermon::pdu_iter e) {
	try {
		//cml.http_request(*this, cp, method, url, hdr, body_start, body_end);
		//std::cout<<"calling cybermon_qwriter http_request::   "<<" write count:"<<writecount<<std::endl;
		//std::cout<<"calling cybermon_qwriter http_request:: url  "<<url;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new http_request_args(cp, method, url, hdr, data);

		//qargs* args = new http_request_args(cp, method, url, hdr, body_start, body_end);
		q_entry* qentry = new q_entry(call_type::http_request, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
		writecount++;
		//std::cout<<" pushed qentry in to q cybermon_qwriter::http_response: "<<cqueue.size()<<"\n";
	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::http_response(const cybermon::context_ptr cp,
		unsigned int code,
		const std::string& status,
		const cybermon::observer::http_hdr_t& hdr,
		const std::string& url,
		cybermon::pdu_iter s,
		cybermon::pdu_iter e) {
	try {
		//cml.http_response(*this, cp, code, status, hdr, url, body_start, body_end);
		//std::cout<<"calling cybermon_qwriter http_response::    "<<" write count:"<<writecount<<std::endl;

		cybermon::pdu data (e-s);
		memcpy(&data[0],&(*s),e-s);
		qargs* args = new http_response_args(cp, code, status, hdr, url, data);
		//qargs* args = new http_response_args(cp, code, status, hdr, url, body_start, body_end);
		q_entry* qentry = new q_entry(call_type::http_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
		writecount++;
		//std::cout<<" pushed qentry in to q cybermon_qwriter::http_response: "<<cqueue.size()<<"\n";

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// SMTP
void cybermon_qwriter::smtp_command(const cybermon::context_ptr cp,
		const std::string& command) {
	try {
		//cml.smtp_command(*this, cp, command);
		//std::cout<<"calling cybermon_qwriter smtp_command::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new smtp_command_args(cp, command);
		q_entry* qentry = new q_entry(call_type::smtp_command, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::smtp_response(const cybermon::context_ptr cp,
		int status,
		const std::list<std::string>& text) {
	try {
		//cml.smtp_response(*this, cp, status, text);
		//std::cout<<"calling cybermon_qwriter smtp_response::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new smtp_response_args(cp, status, text);
		q_entry* qentry = new q_entry(call_type::smtp_response, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::smtp_data(const cybermon::context_ptr cp,
		const std::string& from,
		const std::list<std::string>& to,
		std::vector<unsigned char>::const_iterator s,
		std::vector<unsigned char>::const_iterator e) {
	try {
		//cml.smtp_data(*this, cp, from, to, s, e);

		qargs* args = new smtp_data_args(cp, from, to, s, e);
		q_entry* qentry = new q_entry(call_type::smtp_data, args);

/*
		std::cout<<"calling cybermon_qwriter smtp_data::   "<<" write count:"<<writecount<<std::endl;
		for (std::list<std::string>::const_iterator i = to.begin(); i != to.end(); ++i)
								std::cout << "cybermon_qwriter::smtp_data: to:"<< *i << " "<< std::endl;
*/

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
		//cml.ftp_command(*this, cp, command);
		//std::cout<<"calling cybermon_qwriter ftp_command::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new ftp_command_args(cp, command);
		q_entry* qentry = new q_entry(call_type::ftp_command, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::ftp_response(const cybermon::context_ptr cp,
		int status,
		const std::list<std::string>& responses) {
	try {
		//cml.ftp_response(*this, cp, status, responses);
		//std::cout<<"calling cybermon_qwriter ftp_response::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new ftp_response_args(cp, status, responses);
		q_entry* qentry = new q_entry(call_type::ftp_response, args);
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
		const std::list<cybermon::dns_rr> additional)
{
	try
	{
		//std::cout<<"calling cybermon_qwriter dns_message::   "<<" write count:"<<writecount<<std::endl;

		qargs* args = new dns_message_args(cp,hdr,queries,answers,authorities,additional);

		q_entry* qentry = new q_entry(call_type::dns_message, args);

		lock.lock();
		cqueue.push(qentry);
		lock.unlock();
		writecount++;
		//std::cout<<" pushed qentry in to q cybermon_qwriter::dns_message: "<<cqueue.size()<<"\n";

		//cml.dns_message(*this, cp, hdr, queries, answers, authorities, additional);
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

// NTP
void cybermon_qwriter::ntp_timestamp_message(const cybermon::context_ptr cp,
		const cybermon::ntp_timestamp& ts){
	try {
		//cml.ntp_timestamp_message(*this, cp, ts);
		//std::cout<<"calling cybermon_qwriter ntp_timestamp_message::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new ntp_timestamp_message_args(cp, ts);
		q_entry* qentry = new q_entry(call_type::ntp_timestamp_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::ntp_control_message(const cybermon::context_ptr cp,
		const cybermon::ntp_control& ctrl){
	try {
		//cml.ntp_control_message(*this, cp, ctrl);
		//std::cout<<"calling cybermon_qwriter ntp_control_message::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new ntp_control_message_args(cp, ctrl);
		q_entry* qentry = new q_entry(call_type::ntp_control_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

void cybermon_qwriter::ntp_private_message(const cybermon::context_ptr cp,
		const cybermon::ntp_private& priv){
	try {
		//cml.ntp_private_message(*this, cp, priv);
		//std::cout<<"calling cybermon_qwriter ntp_private_message::   "<<" write count:"<<writecount<<std::endl;
		qargs* args = new ntp_private_message_args(cp, priv);
		q_entry* qentry = new q_entry(call_type::ntp_private_message, args);
		lock.lock();
		cqueue.push(qentry);
		lock.unlock();

	} catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

}
void cybermon_qwriter::close(){
	q_entry* qentry = NULL;
	lock.lock();
	 cqueue.push(qentry);
	 lock.unlock();
	 //std::cout<<" pushed NULL in to q cybermon_qwriter::close "<<cqueue.size()<<" "<<" write count:"<<writecount;
	}




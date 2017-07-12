/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 cybermon_qreader. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.
 Reads q_entry from queue and send it to cybermon::cybermon_lua

 ****************************************************************************/

#include <cybermon_qargs.h>
#include <cybermon_qreader.h>
#include <iostream>
#include <iomanip>
#include <map>
#include <stdint.h>

#include <boost/program_options.hpp>

#include <cybermon/engine.h>
#include <cybermon/context.h>
#include <cybermon/cybermon-lua.h>

cybermon_qreader::cybermon_qreader(const std::string& path,
		std::queue<q_entry*>& cybermonq, threads::mutex& cqwrlock,
		cybermon_qwriter cqwriter) :
		cml(path), cqueue(cybermonq), lock(cqwrlock), qwriter(cqwriter) {
	running = true;
}

// cybermon_qreader thread body - gets PDUs off the queue, and calls the cybermon lua handler.
void cybermon_qreader::run() {

	// Loop until finished.
	while (running) {

		//observed with out this sleep the containers consuming cpu
		if (cqueue.size() == 0) {
			sleep(1);
			continue;
		}

		// Get the lock.
		lock.lock();
		// At this point we hold the lock.

		// Take next packet off queue.
		q_entry* qentry = cqueue.front();
		cqueue.pop();

		if (!qentry) {
			running = false;
			delete (qentry);
			break;
		}

		// Got the packet, so the queue can unlock.
		lock.unlock();
		try {

			switch (qentry->calltype) {

			case call_type::connection_up: {
				connection_args* connectonargs =
						static_cast<connection_args*>(qentry->queueargs);
				cml.connection_up(qwriter, connectonargs->cptr);
				delete (qentry);
				delete (connectonargs);
				break;
			}
			case call_type::connection_down: {
				connection_args* connectonargs =
						static_cast<connection_args*>(qentry->queueargs);
				cml.connection_down(qwriter, connectonargs->cptr);
				delete (qentry);
				delete (connectonargs);
				break;
			}

			case call_type::trigger_up: {
				trigger_up_args* trupargs =
						static_cast<trigger_up_args*>(qentry->queueargs);

				cml.trigger_up(trupargs->trupliid, trupargs->trupaddr);

				delete (qentry);
				delete (trupargs);
				break;
			}
			case call_type::trigger_down: {
				trigger_up_args* trdownargs =
						static_cast<trigger_up_args*>(qentry->queueargs);
				cml.trigger_down(trdownargs->trupliid);
				delete (qentry);
				delete (trdownargs);
				break;
			}
			case call_type::unrecognised_stream: {
				unrecognised_stream_args* ursargs =
						static_cast<unrecognised_stream_args*>(qentry->queueargs);
				cybermon::pdu_iter pdus = ursargs->pdu.begin();
				cybermon::pdu_iter pdue = ursargs->pdu.end();
				cml.unrecognised_stream(qwriter, ursargs->cptr, pdus, pdue);
				delete (qentry);
				delete (ursargs);
				break;
			}
			case call_type::unrecognised_datagram: {
				unrecognised_datagram_args* urdargs =
						static_cast<unrecognised_datagram_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = urdargs->pdu.begin();
				cybermon::pdu_iter pdue = urdargs->pdu.end();
				cml.unrecognised_datagram(qwriter, urdargs->cptr, pdus, pdue);
				delete (qentry);
				delete (urdargs);
				break;
			}
			case call_type::icmp: {

				icmp_args* icmpargs = static_cast<icmp_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = icmpargs->icmpdata.begin();
				cybermon::pdu_iter pdue = icmpargs->icmpdata.end();

				cml.icmp(qwriter, icmpargs->cptr, icmpargs->icmptype,
						icmpargs->icmpcode, pdus, pdue);
				delete (qentry);
				delete (icmpargs);
				break;
			}
			case call_type::imap: {
				imap_args* imapargs = static_cast<imap_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = imapargs->pdu.begin();
				cybermon::pdu_iter pdue = imapargs->pdu.end();

				cml.imap(qwriter, imapargs->cptr, pdus, pdue);
				delete (qentry);
				delete (imapargs);
				break;
			}
			case call_type::imap_ssl: {
				imap_ssl_args* imapsslargs =
						static_cast<imap_ssl_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = imapsslargs->pdu.begin();
				cybermon::pdu_iter pdue = imapsslargs->pdu.end();

				cml.imap_ssl(qwriter, imapsslargs->cptr, pdus, pdue);
				delete (qentry);
				delete (imapsslargs);
				break;
			}
			case call_type::pop3: {
				pop3_args* pop3args = static_cast<pop3_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = pop3args->pdu.begin();
				cybermon::pdu_iter pdue = pop3args->pdu.end();

				cml.pop3(qwriter, pop3args->cptr, pdus, pdue);
				delete (pop3args);
				delete (qentry);
				break;
			}
			case call_type::pop3_ssl: {
				pop3_ssl_args* pop3sslargs =
						static_cast<pop3_ssl_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = pop3sslargs->pdu.begin();
				cybermon::pdu_iter pdue = pop3sslargs->pdu.end();

				cml.pop3_ssl(qwriter, pop3sslargs->cptr, pdus, pdue);
				delete (qentry);
				delete (pop3sslargs);
				break;
			}
			case call_type::rtp: {
				rtp_args* rtpargs = static_cast<rtp_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = rtpargs->pdu.begin();
				cybermon::pdu_iter pdue = rtpargs->pdu.end();

				cml.rtp(qwriter, rtpargs->cptr, pdus, pdue);
				delete (qentry);
				delete (rtpargs);
				break;
			}

			case call_type::rtp_ssl: {
				rtp_ssl_args* rtpsslargs =
						static_cast<rtp_ssl_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = rtpsslargs->pdu.begin();
				cybermon::pdu_iter pdue = rtpsslargs->pdu.end();

				cml.rtp_ssl(qwriter, rtpsslargs->cptr, pdus, pdue);
				delete (qentry);
				delete (rtpsslargs);
				break;
			}
			case call_type::smtp_auth: {
				smtp_auth_args* smtpauthargs =
						static_cast<smtp_auth_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = smtpauthargs->pdu.begin();
				cybermon::pdu_iter pdue = smtpauthargs->pdu.end();

				cml.smtp_auth(qwriter, smtpauthargs->cptr, pdus, pdue);
				delete (qentry);
				delete (smtpauthargs);
				break;
			}
			case call_type::sip_ssl: {
				sip_ssl_args* sipsslargs =
						static_cast<sip_ssl_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = sipsslargs->pdu.begin();
				cybermon::pdu_iter pdue = sipsslargs->pdu.end();

				cml.sip_ssl(qwriter, sipsslargs->cptr, pdus, pdue);
				delete (qentry);
				delete (sipsslargs);
				break;
			}
			case call_type::sip_request: {
				sip_request_args* siprequestargs =
						static_cast<sip_request_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = siprequestargs->pdu.begin();
				cybermon::pdu_iter pdue = siprequestargs->pdu.end();

				cml.sip_request(qwriter, siprequestargs->cptr,
						siprequestargs->sipmethod, siprequestargs->sipfrom,
						siprequestargs->sipto, pdus, pdue);

				delete (qentry);
				delete (siprequestargs);
				break;
			}
			case call_type::sip_response: {
				sip_response_args* sipresponseargs =
						static_cast<sip_response_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = sipresponseargs->pdu.begin();
				cybermon::pdu_iter pdue = sipresponseargs->pdu.end();

				cml.sip_response(qwriter, sipresponseargs->cptr,
						sipresponseargs->sipcode, sipresponseargs->sipstatus,
						sipresponseargs->sipfrom, sipresponseargs->sipto, pdus,
						pdue);
				delete (qentry);
				delete (sipresponseargs);
				break;
			}
			case call_type::http_request: {
				http_request_args* httprequestargs =
						static_cast<http_request_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = httprequestargs->pdu.begin();
				cybermon::pdu_iter pdue = httprequestargs->pdu.end();

				cml.http_request(qwriter, httprequestargs->cptr,
						httprequestargs->httpmethod, httprequestargs->httpurl,
						httprequestargs->httphdr, pdus, pdue);
				delete (qentry);
				delete (httprequestargs);
				break;
			}
			case call_type::http_response: {
				http_response_args* httpresponseargs =
						static_cast<http_response_args*>(qentry->queueargs);

				cybermon::pdu_iter pdus = httpresponseargs->pdu.begin();
				cybermon::pdu_iter pdue = httpresponseargs->pdu.end();

				cml.http_response(qwriter, httpresponseargs->cptr,
						httpresponseargs->httpcode,
						httpresponseargs->httpstatus, httpresponseargs->httphdr,
						httpresponseargs->httpurl, pdus, pdue);
				delete (qentry);
				delete (httpresponseargs);
				break;
			}
			case call_type::smtp_command: {
				smtp_command_args* smtpcommandargs =
						static_cast<smtp_command_args*>(qentry->queueargs);
				cml.smtp_command(qwriter, smtpcommandargs->cptr,
						smtpcommandargs->smtpcommand);
				delete (qentry);
				delete (smtpcommandargs);
				break;
			}
			case call_type::smtp_response: {
				smtp_response_args* smtpresponseargs =
						static_cast<smtp_response_args*>(qentry->queueargs);

				cml.smtp_response(qwriter, smtpresponseargs->cptr,
						smtpresponseargs->smtpstatus,
						smtpresponseargs->smtptext);
				delete (qentry);
				delete (smtpresponseargs);
				break;
			}
			case call_type::smtp_data: {
				smtp_data_args* smtpdataargs =
						static_cast<smtp_data_args*>(qentry->queueargs);

				cml.smtp_data(qwriter, smtpdataargs->cptr,
						smtpdataargs->smtpfrom, smtpdataargs->smtpto,
						smtpdataargs->smtps, smtpdataargs->smtpe);
				delete (qentry);
				delete (smtpdataargs);
				break;
			}
			case call_type::ftp_command: {
				ftp_command_args* ftpcommandargs =
						static_cast<ftp_command_args*>(qentry->queueargs);
				cml.ftp_command(qwriter, ftpcommandargs->cptr,
						ftpcommandargs->ftpcommand);
				delete (qentry);
				delete (ftpcommandargs);
				break;
			}
			case call_type::ftp_response: {
				ftp_response_args* ftpresponseargs =
						static_cast<ftp_response_args*>(qentry->queueargs);
				cml.ftp_response(qwriter, ftpresponseargs->cptr,
						ftpresponseargs->ftpstatus,
						ftpresponseargs->ftpresponses);
				delete (qentry);
				delete (ftpresponseargs);
				break;
			}

			case call_type::dns_message: {

				dns_message_args* dnsargs =
						static_cast<dns_message_args*>(qentry->queueargs);
				cml.dns_message(qwriter, dnsargs->cptr, dnsargs->dnshdr,
						dnsargs->dnsqueries, dnsargs->dnsanswers,
						dnsargs->dnsauthorities, dnsargs->dnsadditional);

				cybermon::dns_query dq = dnsargs->dnsqueries.front();

				delete (qentry);
				delete (dnsargs);
				break;
			}
			case call_type::ntp_timestamp_message: {

				ntp_timestamp_message_args* ntptimestampmessageargs =
						static_cast<ntp_timestamp_message_args*>(qentry->queueargs);

				cml.ntp_timestamp_message(qwriter,
						ntptimestampmessageargs->cptr,
						ntptimestampmessageargs->ntpts);
				delete (qentry);
				delete (ntptimestampmessageargs);
				break;
			}
			case call_type::ntp_control_message: {
				ntp_control_message_args* ntpcontrolmessageargs =
						static_cast<ntp_control_message_args*>(qentry->queueargs);
				cml.ntp_control_message(qwriter, ntpcontrolmessageargs->cptr,
						ntpcontrolmessageargs->ntpctrl);
				delete (qentry);
				delete (ntpcontrolmessageargs);
				break;
			}
			case call_type::ntp_private_message: {
				ntp_private_message_args* ntpprivatemessageargs =
						static_cast<ntp_private_message_args*>(qentry->queueargs);
				cml.ntp_private_message(qwriter, ntpprivatemessageargs->cptr,
						ntpprivatemessageargs->ntppriv);
				delete (qentry);
				delete (ntpprivatemessageargs);
				break;
			}
			default: {
				std::cerr << "unknown call_type cybermon_qreader default:: "<< std::endl;
			}
			}

		} catch (std::exception& e) {

			std::cerr << "cybermon_qreader::run Exception: " << e.what()
					<< std::endl;
		}

	}

}


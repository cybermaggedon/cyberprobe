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

using namespace cybermon;

cybermon_qreader::cybermon_qreader(const std::string& path,
				   std::queue<q_entry*>& cybermonq,
				   threads::mutex& cqwrlock,
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
	    usleep(1000);
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

	    case qargs::connection_up: {
		connection_args* connectionargs =
		    static_cast<connection_args*>(qentry->queueargs);
		cml.connection_up(qwriter, connectionargs->cptr,
				  connectionargs->time);
		delete (qentry);
		delete (connectionargs);
		break;
	    }
	    case qargs::connection_down: {
		connection_args* connectionargs =
		    static_cast<connection_args*>(qentry->queueargs);
		cml.connection_down(qwriter, connectionargs->cptr, connectionargs->time);
		delete (qentry);
		delete (connectionargs);
		break;
	    }

	    case qargs::trigger_up: {
		trigger_up_args* trupargs =
		    static_cast<trigger_up_args*>(qentry->queueargs);

		cml.trigger_up(trupargs->trupliid, trupargs->trupaddr, trupargs->time);

		delete (qentry);
		delete (trupargs);
		break;
	    }
	    case qargs::trigger_down: {
		trigger_up_args* trdownargs =
		    static_cast<trigger_up_args*>(qentry->queueargs);
		cml.trigger_down(trdownargs->trupliid,
				 trdownargs->time);
		delete (qentry);
		delete (trdownargs);
		break;
	    }
	    case qargs::unrecognised_stream: {
		unrecognised_stream_args* ursargs =
		    static_cast<unrecognised_stream_args*>(qentry->queueargs);
		pdu_iter pdus = ursargs->pdu.begin();
		pdu_iter pdue = ursargs->pdu.end();
		cml.unrecognised_stream(qwriter, ursargs->cptr,
					pdus, pdue,
					ursargs->time, ursargs->position);
		delete (qentry);
		delete (ursargs);
		break;
	    }
	    case qargs::unrecognised_datagram: {
		unrecognised_datagram_args* urdargs =
		    static_cast<unrecognised_datagram_args*>(qentry->queueargs);

		pdu_iter pdus = urdargs->pdu.begin();
		pdu_iter pdue = urdargs->pdu.end();
		cml.unrecognised_datagram(qwriter,
					  urdargs->cptr,
					  pdus, pdue,
					  urdargs->time);
		delete (qentry);
		delete (urdargs);
		break;
	    }
	    case qargs::icmp: {

		icmp_args* icmpargs = static_cast<icmp_args*>(qentry->queueargs);

		pdu_iter pdus = icmpargs->icmpdata.begin();
		pdu_iter pdue = icmpargs->icmpdata.end();

		cml.icmp(qwriter, icmpargs->cptr,
			 icmpargs->icmptype,
			 icmpargs->icmpcode, pdus, pdue,
			 icmpargs->time);
		delete (qentry);
		delete (icmpargs);
		break;
	    }
	    case qargs::imap: {
		imap_args* imapargs = static_cast<imap_args*>(qentry->queueargs);

		pdu_iter pdus = imapargs->pdu.begin();
		pdu_iter pdue = imapargs->pdu.end();

		cml.imap(qwriter, imapargs->cptr, pdus, pdue,
			 imapargs->time);
		delete (qentry);
		delete (imapargs);
		break;
	    }
	    case qargs::imap_ssl: {
		imap_ssl_args* imapsslargs =
		    static_cast<imap_ssl_args*>(qentry->queueargs);

		pdu_iter pdus = imapsslargs->pdu.begin();
		pdu_iter pdue = imapsslargs->pdu.end();

		cml.imap_ssl(qwriter, imapsslargs->cptr, pdus, pdue, imapsslargs->time);
		delete (qentry);
		delete (imapsslargs);
		break;
	    }
	    case qargs::pop3: {
		pop3_args* pop3args = static_cast<pop3_args*>(qentry->queueargs);

		pdu_iter pdus = pop3args->pdu.begin();
		pdu_iter pdue = pop3args->pdu.end();

		cml.pop3(qwriter, pop3args->cptr, pdus, pdue, pop3args->time);
		delete (pop3args);
		delete (qentry);
		break;
	    }
	    case qargs::pop3_ssl: {
		pop3_ssl_args* pop3sslargs =
		    static_cast<pop3_ssl_args*>(qentry->queueargs);

		pdu_iter pdus = pop3sslargs->pdu.begin();
		pdu_iter pdue = pop3sslargs->pdu.end();

		cml.pop3_ssl(qwriter, pop3sslargs->cptr, pdus, pdue, pop3sslargs->time);
		delete (qentry);
		delete (pop3sslargs);
		break;
	    }
	    case qargs::rtp: {
		rtp_args* rtpargs = static_cast<rtp_args*>(qentry->queueargs);

		pdu_iter pdus = rtpargs->pdu.begin();
		pdu_iter pdue = rtpargs->pdu.end();

		cml.rtp(qwriter, rtpargs->cptr, pdus, pdue,
			rtpargs->time);
		delete (qentry);
		delete (rtpargs);
		break;
	    }

	    case qargs::rtp_ssl: {
		rtp_ssl_args* rtpsslargs =
		    static_cast<rtp_ssl_args*>(qentry->queueargs);

		pdu_iter pdus = rtpsslargs->pdu.begin();
		pdu_iter pdue = rtpsslargs->pdu.end();

		cml.rtp_ssl(qwriter, rtpsslargs->cptr, pdus, pdue, rtpsslargs->time);
		delete (qentry);
		delete (rtpsslargs);
		break;
	    }
	    case qargs::smtp_auth: {
		smtp_auth_args* smtpauthargs =
		    static_cast<smtp_auth_args*>(qentry->queueargs);

		pdu_iter pdus = smtpauthargs->pdu.begin();
		pdu_iter pdue = smtpauthargs->pdu.end();

		cml.smtp_auth(qwriter, smtpauthargs->cptr, pdus, pdue, smtpauthargs->time);
		delete (qentry);
		delete (smtpauthargs);
		break;
	    }
	    case qargs::sip_ssl: {
		sip_ssl_args* sipsslargs =
		    static_cast<sip_ssl_args*>(qentry->queueargs);

		pdu_iter pdus = sipsslargs->pdu.begin();
		pdu_iter pdue = sipsslargs->pdu.end();

		cml.sip_ssl(qwriter, sipsslargs->cptr, pdus, pdue, sipsslargs->time);
		delete (qentry);
		delete (sipsslargs);
		break;
	    }
	    case qargs::sip_request: {
		sip_request_args* siprequestargs =
		    static_cast<sip_request_args*>(qentry->queueargs);

		pdu_iter pdus = siprequestargs->pdu.begin();
		pdu_iter pdue = siprequestargs->pdu.end();

		cml.sip_request(qwriter, siprequestargs->cptr,
				siprequestargs->sipmethod, siprequestargs->sipfrom,
				siprequestargs->sipto, pdus, pdue, siprequestargs->time);

		delete (qentry);
		delete (siprequestargs);
		break;
	    }
	    case qargs::sip_response: {
		sip_response_args* sipresponseargs =
		    static_cast<sip_response_args*>(qentry->queueargs);

		pdu_iter pdus = sipresponseargs->pdu.begin();
		pdu_iter pdue = sipresponseargs->pdu.end();

		cml.sip_response(qwriter, sipresponseargs->cptr,
				 sipresponseargs->sipcode, sipresponseargs->sipstatus,
				 sipresponseargs->sipfrom, sipresponseargs->sipto, pdus,
				 pdue, sipresponseargs->time);
		delete (qentry);
		delete (sipresponseargs);
		break;
	    }
	    case qargs::http_request: {
		http_request_args* httprequestargs =
		    static_cast<http_request_args*>(qentry->queueargs);

		pdu_iter pdus = httprequestargs->pdu.begin();
		pdu_iter pdue = httprequestargs->pdu.end();

		cml.http_request(qwriter, httprequestargs->cptr,
				 httprequestargs->httpmethod, httprequestargs->httpurl,
				 httprequestargs->httphdr, pdus, pdue, httprequestargs->time);
		delete (qentry);
		delete (httprequestargs);
		break;
	    }
	    case qargs::http_response: {
		http_response_args* httpresponseargs =
		    static_cast<http_response_args*>(qentry->queueargs);

		pdu_iter pdus = httpresponseargs->pdu.begin();
		pdu_iter pdue = httpresponseargs->pdu.end();

		cml.http_response(qwriter, httpresponseargs->cptr,
				  httpresponseargs->httpcode,
				  httpresponseargs->httpstatus, httpresponseargs->httphdr,
				  httpresponseargs->httpurl, pdus, pdue, httpresponseargs->time);
		delete (qentry);
		delete (httpresponseargs);
		break;
	    }
	    case qargs::smtp_command: {
		smtp_command_args* smtpcommandargs =
		    static_cast<smtp_command_args*>(qentry->queueargs);
		cml.smtp_command(qwriter, smtpcommandargs->cptr,
				 smtpcommandargs->smtpcommand, smtpcommandargs->time);
		delete (qentry);
		delete (smtpcommandargs);
		break;
	    }
	    case qargs::smtp_response: {
		smtp_response_args* smtpresponseargs =
		    static_cast<smtp_response_args*>(qentry->queueargs);

		cml.smtp_response(qwriter, smtpresponseargs->cptr,
				  smtpresponseargs->smtpstatus,
				  smtpresponseargs->smtptext, smtpresponseargs->time);
		delete (qentry);
		delete (smtpresponseargs);
		break;
	    }
	    case qargs::smtp_data: {
		smtp_data_args* smtpdataargs =
		    static_cast<smtp_data_args*>(qentry->queueargs);

		cml.smtp_data(qwriter, smtpdataargs->cptr,
			      smtpdataargs->smtpfrom, smtpdataargs->smtpto,
			      smtpdataargs->smtps, smtpdataargs->smtpe, smtpdataargs->time);
		delete (qentry);
		delete (smtpdataargs);
		break;
	    }
	    case qargs::ftp_command: {
		ftp_command_args* ftpcommandargs =
		    static_cast<ftp_command_args*>(qentry->queueargs);
		cml.ftp_command(qwriter, ftpcommandargs->cptr,
				ftpcommandargs->ftpcommand, ftpcommandargs->time);
		delete (qentry);
		delete (ftpcommandargs);
		break;
	    }
	    case qargs::ftp_response: {
		ftp_response_args* ftpresponseargs =
		    static_cast<ftp_response_args*>(qentry->queueargs);
		cml.ftp_response(qwriter, ftpresponseargs->cptr,
				 ftpresponseargs->ftpstatus,
				 ftpresponseargs->ftpresponses, ftpresponseargs->time);
		delete (qentry);
		delete (ftpresponseargs);
		break;
	    }

	    case qargs::dns_message: {

		dns_message_args* dnsargs =
		    static_cast<dns_message_args*>(qentry->queueargs);
		cml.dns_message(qwriter, dnsargs->cptr, dnsargs->dnshdr,
				dnsargs->dnsqueries, dnsargs->dnsanswers,
				dnsargs->dnsauthorities, dnsargs->dnsadditional, dnsargs->time);

		dns_query dq = dnsargs->dnsqueries.front();

		delete (qentry);
		delete (dnsargs);
		break;
	    }
	    case qargs::ntp_timestamp_message: {

		ntp_timestamp_message_args* ntptimestampmessageargs =
		    static_cast<ntp_timestamp_message_args*>(qentry->queueargs);

		cml.ntp_timestamp_message(qwriter,
					  ntptimestampmessageargs->cptr,
					  ntptimestampmessageargs->ntpts,
					  ntptimestampmessageargs->time);
		delete (qentry);
		delete (ntptimestampmessageargs);
		break;
	    }
	    case qargs::ntp_control_message: {
		ntp_control_message_args* ntpcontrolmessageargs =
		    static_cast<ntp_control_message_args*>(qentry->queueargs);
		cml.ntp_control_message(qwriter, ntpcontrolmessageargs->cptr,
					ntpcontrolmessageargs->ntpctrl, ntpcontrolmessageargs->time);
		delete (qentry);
		delete (ntpcontrolmessageargs);
		break;
	    }
	    case qargs::ntp_private_message: {
		ntp_private_message_args* ntpprivatemessageargs =
		    static_cast<ntp_private_message_args*>(qentry->queueargs);
		cml.ntp_private_message(qwriter, ntpprivatemessageargs->cptr,
					ntpprivatemessageargs->ntppriv, ntpprivatemessageargs->time);
		delete (qentry);
		delete (ntpprivatemessageargs);
		break;
	    }
	    case qargs::gre_message: {
		gre_args* greMessageArgs =
		    static_cast<gre_args*>(qentry->queueargs);
		cml.gre_message(qwriter, greMessageArgs->cptr,
					greMessageArgs->nextProto, greMessageArgs->key, greMessageArgs->sequenceNo,
					greMessageArgs->pdu.begin(), greMessageArgs->pdu.end(), greMessageArgs->time);
		delete (qentry);
		delete (greMessageArgs);
		break;
	    }
	    case qargs::gre_pptp_message: {
		gre_pptp_args* grePptpMessageArgs =
		    static_cast<gre_pptp_args*>(qentry->queueargs);
		cml.gre_pptp_message(qwriter, grePptpMessageArgs->cptr,
					grePptpMessageArgs->nextProto, grePptpMessageArgs->payload_length, grePptpMessageArgs->call_id,
					grePptpMessageArgs->sequenceNo, grePptpMessageArgs->ackNo,
					grePptpMessageArgs->pdu.begin(), grePptpMessageArgs->pdu.end(), grePptpMessageArgs->time);
		delete (qentry);
		delete (grePptpMessageArgs);
		break;
	    }
	    case qargs::esp: {
		esp_args* espArgs =
		    static_cast<esp_args*>(qentry->queueargs);
		cml.esp(qwriter, espArgs->cptr, espArgs->spi, espArgs->sequence, espArgs->length,
					espArgs->pdu.begin(), espArgs->pdu.end(), espArgs->time);
		delete (qentry);
		delete (espArgs);
		break;
	    }
	    case qargs::unrecognised_ip_protocol: {
		unknown_ip_proto_args* unknownIpProtoArgs =
		    static_cast<unknown_ip_proto_args*>(qentry->queueargs);
		cml.unrecognised_ip_protocol(qwriter, unknownIpProtoArgs->cptr, unknownIpProtoArgs->nxtProto,
					unknownIpProtoArgs->length, unknownIpProtoArgs->pdu.begin(), unknownIpProtoArgs->pdu.end(),
					unknownIpProtoArgs->time);
		delete (qentry);
		delete (unknownIpProtoArgs);
		break;
	    }
	    case qargs::wlan: {
		wlan_args* wlanArgs =
		    static_cast<wlan_args*>(qentry->queueargs);
		cml.wlan(qwriter, wlanArgs->cptr, wlanArgs->version, wlanArgs->type, wlanArgs->subtype,
			wlanArgs->flags, wlanArgs->is_protected, wlanArgs->duration, wlanArgs->filt_addr,
			wlanArgs->frag_num, wlanArgs->seq_num, wlanArgs->time);
		delete (qentry);
		delete (wlanArgs);
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



/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

Simple queue reader. Part of new queue implementation to address frequent cybermon
crashes caused due to limitation of lua threading.
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

cybermon_qreader::cybermon_qreader(const std::string& path, std::queue<q_entry*>& cybermonq, threads::mutex& cqwrlock, cybermon_qwriter cqwriter) :
cml(path), cqueue(cybermonq), lock(cqwrlock), qwriter(cqwriter) , readcount(0), dnsreadcount(0), smtpdatareadcount(0), smtpresponsereadcount(0),
ntptimestampmessagereadcount(0), icmpreadcount(0){
	running = true;
}

// cybermon_qreader thread body - gets PDUs off the queue, and calls the cybermon lua handler.
void cybermon_qreader::run()
{




    // Loop until finished.
    while (running) {

    	//std::cout<<" called cybermon_qreader::run 1 and cqueue.size():" <<cqueue.size()<<" \n";

	// Loop until the input queue is empty.
	while (cqueue.size() > 0) {

		 // Get the lock.
		 lock.lock();
	    // At this point we hold the lock.

		//std::cout<<" called cybermon_qreader::run 2 \n";

	    // Take next packet off queue.
		q_entry* qentry = cqueue.front();
		cqueue.pop();
	    readcount++;

	    //std::cout << "received ptr " << qentry<< " "<<" read count:"<<readcount <<std::endl;

		if(!qentry){
			running = false;
			//std::cout<<"exiting from cybermon_qreader::run:" <<cqueue.size()<<" "<<" read count:"<<readcount << std::endl;
			delete(qentry);
			break;
		}


	    // Got the packet, so the queue can unlock.
	    lock.unlock();

	    //std::cout<<" popped a qentry from q cybermon_qreader::run:" <<cqueue.size()<<" \n";

	    //std::cout<<" called cybermon_qreader::run 3 \n";

		try {

			//std::cout<<" called cybermon_qreader::run 4 \n";

			switch(qentry->calltype){

				case call_type::connection_up:{
					//std::cout<<"calling connection_up:: \n";
					connection_args* connectonargs =  static_cast<connection_args*> (qentry->queueargs);
					cml.connection_up(qwriter, connectonargs->cptr);
					delete(qentry);
					delete(connectonargs);
					//std::cout<<"done connection_up:: \n";
					break;
				}
				case call_type::connection_down:{
					//std::cout<<"calling connection_down:: \n";
					connection_args* connectonargs =  static_cast<connection_args*> (qentry->queueargs);
					cml.connection_down(qwriter, connectonargs->cptr);
					delete(qentry);
					delete(connectonargs);
					//std::cout<<"done connection_down:: \n";
					break;
				}

				case call_type::trigger_up:{
					std::cout<<"calling trigger_up:: \n";

					trigger_up_args* trupargs =  static_cast<trigger_up_args*> (qentry->queueargs);

					cml.trigger_up(trupargs->trupliid, trupargs->trupaddr);

					delete(qentry);
					delete(trupargs);
					std::cout<<"done trigger_up:: \n";
					break;
				}
				case call_type::trigger_down:{
					//std::cout<<"calling trigger_down:: \n";
					trigger_up_args* trdownargs =  static_cast<trigger_up_args*> (qentry->queueargs);
					cml.trigger_down(trdownargs->trupliid);
					delete(qentry);
					delete(trdownargs);
					//std::cout<<"done trigger_down:: \n";
					break;
				}
				case call_type::unrecognised_stream:{
					//std::cout<<"calling unrecognised_stream:: \n";
					unrecognised_stream_args* ursargs =  static_cast<unrecognised_stream_args*> (qentry->queueargs);
					cybermon::pdu_iter pdus = ursargs->pdu.begin();
					cybermon::pdu_iter pdue = ursargs->pdu.end();
					cml.unrecognised_stream(qwriter, ursargs->cptr, pdus, pdue);
					//cml.unrecognised_stream(qwriter, ursargs->cptr, ursargs->pdus, ursargs->pdue);
					delete(qentry);
					delete(ursargs);
					//std::cout<<"done unrecognised_stream:: \n";
					break;
				}
				case call_type::unrecognised_datagram:{
					//std::cout<<"calling unrecognised_datagram:: \n";
					unrecognised_datagram_args* urdargs =  static_cast<unrecognised_datagram_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = urdargs->pdu.begin();
					cybermon::pdu_iter pdue = urdargs->pdu.end();
					cml.unrecognised_datagram(qwriter, urdargs->cptr, pdus, pdue);

					//cml.unrecognised_datagram(qwriter, urdargs->cptr, urdargs->pdus, urdargs->pdue);
					delete(qentry);
					delete(urdargs);
					//std::cout<<"done unrecognised_datagram:: \n";
					break;
				}
				case call_type::icmp:{

					icmpreadcount++;
					icmp_args* icmpargs =  static_cast<icmp_args*> (qentry->queueargs);

					//std::cout<<"calling cybermon_qreader::icmp:  "<<" icmpreadcount: "<<icmpreadcount<<std::endl;

					/*lock.lock();
					std::cerr << "cybermon_qreader::icmp::";

					for (cybermon::pdu_iter i = icmpargs->pdus; i != icmpargs->pdue ; ++i)
						std::cerr<< std::setw(2)<<std::setfill('0')<<std::hex << static_cast<uint16_t> (*i) ;

					std::cerr<<std::endl;
					lock.unlock();*/

					cybermon::pdu_iter pdus = icmpargs->icmpdata.begin();
					cybermon::pdu_iter pdue = icmpargs->icmpdata.end();

					/*lock.lock();
					std::cerr << "cybermon_qreader::icmp::";

					for (cybermon::pdu_iter i = pdus; i != pdue ; ++i)
						std::cerr<< std::setw(2)<<std::setfill('0')<<std::hex << static_cast<uint16_t> (*i) ;

					std::cerr<<std::endl;
					lock.unlock();*/

					cml.icmp(qwriter, icmpargs->cptr, icmpargs->icmptype, icmpargs->icmpcode, pdus, pdue);

					//std::cout<<"done cybermon_qreader::icmp::"<< " "<< std::endl;

					delete(qentry);
					delete(icmpargs);
					break;
				}
				case call_type::imap:{
					//std::cout<<"calling imap:: \n";
					imap_args* imapargs =  static_cast<imap_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = imapargs->pdu.begin();
					cybermon::pdu_iter pdue = imapargs->pdu.end();

					cml.imap(qwriter, imapargs->cptr, pdus, pdue);
					//cml.imap(qwriter, imapargs->cptr, imapargs->pdus, imapargs->pdue);
					//std::cout<<"done imap:: \n";
					delete(qentry);
					delete(imapargs);
					break;
				}
				case call_type::imap_ssl:{
					//std::cout<<"calling imap_ssl:: \n";
					imap_ssl_args* imapsslargs =  static_cast<imap_ssl_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = imapsslargs->pdu.begin();
					cybermon::pdu_iter pdue = imapsslargs->pdu.end();

					cml.imap_ssl(qwriter, imapsslargs->cptr, pdus, pdue);
					//cml.imap_ssl(qwriter, imapsslargs->cptr, imapsslargs->pdus, imapsslargs->pdue);
					//std::cout<<"done imap_ssl:: \n";
					delete(qentry);	cqueue.pop();
					delete(imapsslargs);
					break;
				}
				case call_type::pop3:{
					//std::cout<<"calling pop3:: \n";
					pop3_args* pop3args =  static_cast<pop3_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = pop3args->pdu.begin();
					cybermon::pdu_iter pdue = pop3args->pdu.end();

					cml.pop3(qwriter, pop3args->cptr, pdus, pdue);
					//cml.pop3(qwriter, pop3args->cptr, pop3args->pdus, pop3args->pdue);
					//std::cout<<"done pop3:: \n";
					delete(pop3args);
					delete(qentry);
					break;
				}
				case call_type::pop3_ssl:{
					//std::cout<<"calling pop3_ssl:: \n";
					pop3_ssl_args* pop3sslargs =  static_cast<pop3_ssl_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = pop3sslargs->pdu.begin();
					cybermon::pdu_iter pdue = pop3sslargs->pdu.end();

					cml.pop3_ssl(qwriter, pop3sslargs->cptr, pdus, pdue);

					//cml.pop3_ssl(qwriter, pop3sslargs->cptr, pop3sslargs->pdus, pop3sslargs->pdue);
					//std::cout<<"done pop3_ssl:: \n";
					delete(qentry);
					delete(pop3sslargs);
					break;
				}
				case call_type::rtp:{
					//std::cout<<"calling rtp:: \n";
					rtp_args* rtpargs =  static_cast<rtp_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = rtpargs->pdu.begin();
					cybermon::pdu_iter pdue = rtpargs->pdu.end();

					cml.rtp(qwriter, rtpargs->cptr, pdus, pdue);
					//cml.rtp(qwriter, rtpargs->cptr, rtpargs->pdus, rtpargs->pdue);
					//std::cout<<"done rtp:: \n";
					delete(qentry);
					delete(rtpargs);
					break;
				}

				case call_type::rtp_ssl:{
					//std::cout<<"calling rtp_ssl:: \n";
					rtp_ssl_args* rtpsslargs =  static_cast<rtp_ssl_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = rtpsslargs->pdu.begin();
					cybermon::pdu_iter pdue = rtpsslargs->pdu.end();

					cml.rtp_ssl(qwriter, rtpsslargs->cptr, pdus, pdue);
					//cml.rtp_ssl(qwriter, rtpsslargs->cptr, rtpsslargs->pdus, rtpsslargs->pdue);
					//std::cout<<"done rtp_ssl:: \n";
					delete(qentry);
					delete(rtpsslargs);
					break;
				}
				case call_type::smtp_auth:{
					//std::cout<<"calling smtp_auth:: \n";
					smtp_auth_args* smtpauthargs =  static_cast<smtp_auth_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = smtpauthargs->pdu.begin();
					cybermon::pdu_iter pdue = smtpauthargs->pdu.end();

					cml.smtp_auth(qwriter, smtpauthargs->cptr, pdus, pdue);
					//cml.smtp_auth(qwriter, smtpauthargs->cptr, smtpauthargs->pdus, smtpauthargs->pdue);
					//std::cout<<"done smtp_auth:: \n";
					delete(qentry);
					delete(smtpauthargs);
					break;
				}
				case call_type::sip_ssl:{
					//std::cout<<"calling sip_ssl:: \n";
					sip_ssl_args* sipsslargs =  static_cast<sip_ssl_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = sipsslargs->pdu.begin();
					cybermon::pdu_iter pdue = sipsslargs->pdu.end();

					cml.sip_ssl(qwriter, sipsslargs->cptr, pdus, pdue);
					//cml.sip_ssl(qwriter, sipsslargs->cptr, sipsslargs->pdus, sipsslargs->pdue);
					//std::cout<<"done sip_ssl:: \n";
					delete(qentry);
					delete(sipsslargs);
					break;
				}
				case call_type::sip_request:{
					//std::cout<<"calling sip_request:: \n";
					sip_request_args* siprequestargs =  static_cast<sip_request_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = siprequestargs->pdu.begin();
					cybermon::pdu_iter pdue = siprequestargs->pdu.end();

					cml.sip_request(qwriter, siprequestargs->cptr, siprequestargs->sipmethod, siprequestargs->sipfrom, siprequestargs->sipto, pdus, pdue);

					//cml.sip_request(qwriter, siprequestargs->cptr, siprequestargs->sipmethod, siprequestargs->sipfrom, siprequestargs->sipto, siprequestargs->pdus, siprequestargs->pdue);
					//std::cout<<"done sip_request:: \n";
					delete(qentry);
					delete(siprequestargs);
					break;
				}
				case call_type::sip_response:{
					//std::cout<<"calling sip_response:: \n";
					sip_response_args* sipresponseargs =  static_cast<sip_response_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = sipresponseargs->pdu.begin();
					cybermon::pdu_iter pdue = sipresponseargs->pdu.end();

					cml.sip_response(qwriter, sipresponseargs->cptr, sipresponseargs->sipcode, sipresponseargs->sipstatus, sipresponseargs->sipfrom, sipresponseargs->sipto, pdus, pdue);

					//cml.sip_response(qwriter, sipresponseargs->cptr, sipresponseargs->sipcode, sipresponseargs->sipstatus, sipresponseargs->sipfrom, sipresponseargs->sipto, sipresponseargs->pdus, sipresponseargs->pdue);
					//std::cout<<"done sip_response:: \n";
					delete(qentry);
					delete(sipresponseargs);
					break;
				}
				case call_type::http_request:{
					//std::cout<<"calling cybermon_qreader http_request::  "<<" read count:"<<readcount<<std::endl;
					http_request_args* httprequestargs =  static_cast<http_request_args*> (qentry->queueargs);
					//std::cout<<"calling cybermon_qreader http_request::  "<<" httprequestargs->cptr:"<<httprequestargs->cptr<<std::endl;
					//std::cout<<"calling cybermon_qreader http_request::  "<<" httprequestargs->httpmethod:"<<httprequestargs->httpmethod<<std::endl;

					//if(!httprequestargs->httphdr.empty())std::cout<<"calling cybermon_qreader http_request::  "<<" i am good"<<std::endl;
					//std::cout<<"calling cybermon_qreader http_request::  "<<" httprequestargs->httpurl:"<<httprequestargs->httpurl<<std::endl;
					//std::cout<<"calling cybermon_qreader http_request::  "<<" httprequestargs->pdus:"<<httprequestargs->pdus<<std::endl;
					//std::cout<<"calling cybermon_qreader http_request::  "<<" httprequestargs->pdue:"<<httprequestargs->pdue<<std::endl;
					//std::string url = "";

					cybermon::pdu_iter pdus = httprequestargs->pdu.begin();
					cybermon::pdu_iter pdue = httprequestargs->pdu.end();

					//std::cerr <<"http_request url:"<<httprequestargs->httpurl;

					/*for(std::map<std::string, std::pair<std::string,std::string>>::const_iterator  it = httprequestargs->httphdr.begin(); it != httprequestargs->httphdr.end(); ++it)
										{
										    std::cerr << it->first << ":here1:" << it->second.first << ":here2:" << it->second.second <<std::endl;
										}
*/

					cml.http_request(qwriter, httprequestargs->cptr, httprequestargs->httpmethod, httprequestargs->httpurl, httprequestargs->httphdr, pdus, pdue);
					//cml.http_request(qwriter, httprequestargs->cptr, httprequestargs->httpmethod, httprequestargs->httpurl, httprequestargs->httphdr, httprequestargs->pdus, httprequestargs->pdue);
					//std::cout<<"done http_request:: \n";
					delete(qentry);
					delete(httprequestargs);
					break;
				}
				case call_type::http_response:{
					//std::cout<<"calling cybermon_qreader http_response::   "<<" read count:"<<readcount<<std::endl;
					http_response_args* httpresponseargs =  static_cast<http_response_args*> (qentry->queueargs);

					cybermon::pdu_iter pdus = httpresponseargs->pdu.begin();
					cybermon::pdu_iter pdue = httpresponseargs->pdu.end();

					//std::cerr <<"http_response url:"<<httpresponseargs->httpurl;

					//std::cout<<"calling cybermon_qreader http_response::   "<<"  httpresponseargs->httphdr:"<< httpresponseargs->httphdr<<std::endl;

					//std::map<std::string, std::pair<std::string,std::string>> myMap = httpresponseargs->httphdr.

				/*	for(std::map<std::string, std::pair<std::string,std::string>>::const_iterator  it = httpresponseargs->httphdr.begin(); it != httpresponseargs->httphdr.end(); ++it)
					{
					    std::cerr << it->first << " " << it->second.first << " " << it->second.second <<std::endl;
					}
*/
					cml.http_response(qwriter, httpresponseargs->cptr, httpresponseargs->httpcode, httpresponseargs->httpstatus, httpresponseargs->httphdr, httpresponseargs->httpurl, pdus, pdue);
					//cml.http_response(qwriter, httpresponseargs->cptr, httpresponseargs->httpcode, httpresponseargs->httpstatus, httpresponseargs->httphdr, httpresponseargs->httpurl, httpresponseargs->pdus, httpresponseargs->pdue);
					//std::cout<<"done http_response:: \n";
					delete(qentry);
					delete(httpresponseargs);
					break;
				}
				case call_type::smtp_command:{
					//std::cout<<"calling smtp_command:: \n";
					smtp_command_args* smtpcommandargs =  static_cast<smtp_command_args*> (qentry->queueargs);
					cml.smtp_command(qwriter, smtpcommandargs->cptr, smtpcommandargs->smtpcommand);
					//std::cout<<"done smtp_command:: \n";
					delete(qentry);
					delete(smtpcommandargs);
					break;
				}
				case call_type::smtp_response:{
					smtpresponsereadcount++;
					smtp_response_args* smtpresponseargs =  static_cast<smtp_response_args*> (qentry->queueargs);
					/*
					std::cout << "cybermon_qreader::smtp_response: smtpresponsereadcount " << smtpresponsereadcount << " " << std::endl;
					std::cout << "cybermon_qreader::smtp_response: smtpstatus:"<< smtpresponseargs->smtpstatus << " " << std::endl;

					for (std::list<std::string>::const_iterator i = smtpresponseargs->smtptext.begin(); i != smtpresponseargs->smtptext.end(); ++i)
										std::cout << "cybermon_qreader::smtp_response: smtptext:"<< *i << " "<< std::endl;
					*/

					cml.smtp_response(qwriter, smtpresponseargs->cptr, smtpresponseargs->smtpstatus, smtpresponseargs->smtptext);
					//std::cout<<"done cybermon_qreader::smtp_response::"<< " "<< std::endl;
					delete(qentry);
					delete(smtpresponseargs);
					break;
				}
				case call_type::smtp_data:{
					smtpdatareadcount++;
					smtp_data_args* smtpdataargs =  static_cast<smtp_data_args*> (qentry->queueargs);

					/* std::cout << "cybermon_qreader::smtp_data: smtpdatareadcount " << smtpdatareadcount << " " << std::endl;
					std::cout << "cybermon_qreader::smtp_data: smtpfrom:"<< smtpdataargs->smtpfrom << " " << std::endl;

					for (std::list<std::string>::const_iterator i = smtpdataargs->smtpto.begin(); i != smtpdataargs->smtpto.end(); ++i)
						std::cout << "cybermon_qreader::smtp_data: smtpto:"<< *i << " "<< std::endl;

					*///std::cout << "smtp_data: smtps:"<< smtpdataargs->smtps<< " " << std::endl;
					//std::cout << "smtp_data: smtpe:"<< smtpdataargs->smtpe<< " " << std::endl;

					cml.smtp_data(qwriter, smtpdataargs->cptr, smtpdataargs->smtpfrom, smtpdataargs->smtpto, smtpdataargs->smtps, smtpdataargs->smtpe);
					//std::cout<<"done cybermon_qreader::smtp_data::"<< " "<< std::endl;
					delete(qentry);
					delete(smtpdataargs);
					break;
				}
				case call_type::ftp_command:{
					//std::cout<<"calling ftp_command:: \n";
					ftp_command_args* ftpcommandargs =  static_cast<ftp_command_args*> (qentry->queueargs);
					cml.ftp_command(qwriter, ftpcommandargs->cptr, ftpcommandargs->ftpcommand);
					//std::cout<<"done ftp_command:: \n";
					delete(qentry);
					delete(ftpcommandargs);
					break;
				}
				case call_type::ftp_response:{
					//std::cout<<"calling ftp_response:: \n";
					ftp_response_args* ftpresponseargs =  static_cast<ftp_response_args*> (qentry->queueargs);
					cml.ftp_response(qwriter, ftpresponseargs->cptr, ftpresponseargs->ftpstatus, ftpresponseargs->ftpresponses) ;
					//std::cout<<"done ftp_response:: \n";
					delete(qentry);
					delete(ftpresponseargs);
					break;
				}

				case call_type::dns_message:{
					//std::cout<<"calling dns_message:: \n";
					dnsreadcount++;
					//std::cout << "read " << dnsreadcount << " dns messages" << std::endl;
					dns_message_args* dnsargs =  static_cast<dns_message_args*> (qentry->queueargs);
					cml.dns_message(qwriter, dnsargs->cptr, dnsargs->dnshdr, dnsargs->dnsqueries, dnsargs->dnsanswers, dnsargs->dnsauthorities, dnsargs->dnsadditional);

					cybermon::dns_query dq = dnsargs->dnsqueries.front();

					//std::cout<<" cybermon_qreader::run 5 processing qentry \n";

					//std::cout<<"dns_query name:"<<dq.name<<"\n";

					//std::cout<<" cybermon_qreader::run 7 processing qentry dnshdr: "<< (dnsargs->dnshdr.id)<<" \n";
					//std::cout<<" cybermon_qreader::run 8 processing qentry dnsqueries: "<< (dnsargs->dnsqueries.size())<<" \n";
					//std::cout<<" cybermon_qreader::run 9 processing qentry dnsanswers: "<< (dnsargs->dnsanswers.size())<<" \n";
					//std::cout<<" cybermon_qreader::run 10 processing qentry dnsauthorities: "<< (dnsargs->dnsauthorities.size())<<" \n";
					//std::cout<<" cybermon_qreader::run 11 processing qentry dnsadditional: "<< (dnsargs->dnsadditional.size())<<" \n";
					//std::cout<<" cybermon_qreader::run 12 processing qentry cptr: "<< dnsargs->cptr<<" \n";
					delete(qentry);
					delete(dnsargs);
					break;
				}
				case call_type::ntp_timestamp_message:{

					ntptimestampmessagereadcount++;


					ntp_timestamp_message_args* ntptimestampmessageargs =  static_cast<ntp_timestamp_message_args*> (qentry->queueargs);

					/*std::cout << "cybermon_qreader::ntp_timestamp_message: ntptimestampmessagereadcount :" << ntptimestampmessagereadcount << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_has_extension:"<< ntptimestampmessageargs->ntpts.m_has_extension << " " << std::endl;

					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_originate_timestamp:"<< ntptimestampmessageargs->ntpts.m_originate_timestamp << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_poll:"<< ntptimestampmessageargs->ntpts.m_poll << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_precision:"<< ntptimestampmessageargs->ntpts.m_precision << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_receive_timestamp:"<< ntptimestampmessageargs->ntpts.m_receive_timestamp << " " << std::endl;

					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_reference_id:"<< ntptimestampmessageargs->ntpts.m_reference_id << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_reference_timestamp:"<< ntptimestampmessageargs->ntpts.m_reference_timestamp << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_root_delay:"<< ntptimestampmessageargs->ntpts.m_root_delay << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_root_dispersion:"<< ntptimestampmessageargs->ntpts.m_root_dispersion << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_stratum:"<< ntptimestampmessageargs->ntpts.m_stratum << " " << std::endl;
					std::cout << "cybermon_qreader::ntp_timestamp_message: ntpts.m_transmit_timestamp:"<< ntptimestampmessageargs->ntpts.m_transmit_timestamp << " " << std::endl;

					*/
					cml.ntp_timestamp_message(qwriter, ntptimestampmessageargs->cptr, ntptimestampmessageargs->ntpts) ;
					//std::cout<<"done cybermon_qreader::ntp_timestamp_message::"<< " "<< std::endl;
					delete(qentry);
					delete(ntptimestampmessageargs);
					break;
				}
				case call_type::ntp_control_message:{
					//std::cout<<"calling ntp_control_message:: \n";
					ntp_control_message_args* ntpcontrolmessageargs =  static_cast<ntp_control_message_args*> (qentry->queueargs);
					cml.ntp_control_message(qwriter, ntpcontrolmessageargs->cptr, ntpcontrolmessageargs->ntpctrl) ;
					//std::cout<<"done ntp_control_message:: \n";
					delete(qentry);
					delete(ntpcontrolmessageargs);
					break;
				}
				case call_type::ntp_private_message:{
					//std::cout<<"calling ntp_private_message:: \n";
					ntp_private_message_args* ntpprivatemessageargs =  static_cast<ntp_private_message_args*> (qentry->queueargs);
					cml.ntp_private_message(qwriter, ntpprivatemessageargs->cptr, ntpprivatemessageargs->ntppriv) ;
					//std::cout<<"done ntp_private_message:: \n";
					delete(qentry);
					delete(ntpprivatemessageargs);
					break;
				}
				default:
				{
					std::cout<<"calling cybermon_qreader default:: "<< readcount << std::endl;
				}
			}

			/*dns_message_args* args =  static_cast<dns_message_args*> (qentry->queueargs);


			cybermon::dns_query dq = args->dnsqueries.front();

			std::cout<<" cybermon_qreader::run 5 processing qentry \n";

			std::cout<<"dns_query name:"<<dq.name<<"\n";

			std::cout<<" cybermon_qreader::run 7 processing qentry dnshdr: "<< (args->dnshdr.id)<<" \n";
			std::cout<<" cybermon_qreader::run 8 processing qentry dnsqueries: "<< (args->dnsqueries.size())<<" \n";
			std::cout<<" cybermon_qreader::run 9 processing qentry dnsanswers: "<< (args->dnsanswers.size())<<" \n";
			std::cout<<" cybermon_qreader::run 10 processing qentry dnsauthorities: "<< (args->dnsauthorities.size())<<" \n";
			std::cout<<" cybermon_qreader::run 11 processing qentry dnsadditional: "<< (args->dnsadditional.size())<<" \n";
			std::cout<<" cybermon_qreader::run 12 processing qentry cptr: "<< args->cptr<<" \n";

			cml.dns_message(qwriter, args->cptr, args->dnshdr, args->dnsqueries, args->dnsanswers, args->dnsauthorities, args->dnsadditional);
*/
			//std::cout<<" cybermon_qreader::run 13 processed qentry \n";

		} catch (std::exception& e) {

			std::cerr << "cybermon_qreader::run Exception: " << e.what() << std::endl;
		    // Wait and retry.
		    ::sleep(1);
		}



	}

    }


}




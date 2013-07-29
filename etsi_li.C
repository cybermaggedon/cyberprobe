
#include <fstream>
#include "etsi_li.h"
#include "ber.h"

// Support for a simple usage of ETSI LI protocol, defined in ETSI TS 102 232.

using namespace etsi_li;

// The next CIN which will be used.
unsigned long mux::next_cin = 0;

// Encodes the ETSI LI PS PDU PSHeader construct.
void sender::encode_psheader(ber::berpdu& psheader_p,
			     const std::string& liid,
			     const std::string& oper,
			     long seq, long cin,
			     const std::string& country,
			     const std::string& net_element,
			     const std::string& intpt)
{

    // Create a time string, GeneralizedTime.
    char tms[128];
    {
	time_t now = time(0);
	struct tm res;
	struct tm* ts = gmtime_r(&now, &res);
	strftime(tms, 128, "%Y%m%d%H%M%SZ", ts);
    }

    std::list<ber::berpdu*> pdus;

    // ----------------------------------------------------------------------
    // Encode Network identifier
    // ----------------------------------------------------------------------

    // Operator ID
    ber::berpdu operid_p;
    operid_p.encode_string(ber::context_specific, 0, oper);

    // network element
    ber::berpdu netelt_p;
    netelt_p.encode_string(ber::context_specific, 1, net_element);

    // NetworkIdentifier
    ber::berpdu neid_p;
    pdus.clear();
    pdus.push_back(&operid_p);
    pdus.push_back(&netelt_p);
    neid_p.encode_construct(ber::context_specific, 0, pdus);

    // ----------------------------------------------------------------------
    // Encode CID
    // ----------------------------------------------------------------------

    // CIN
    ber::berpdu cin_p;
    cin_p.encode_int(ber::context_specific, 1, cin);

    // Deliv country
    ber::berpdu deliv_cc_p;
    deliv_cc_p.encode_string(ber::context_specific, 2, country);

    // Encode CID
    ber::berpdu cid_p;
    pdus.clear();
    pdus.push_back(&neid_p);
    pdus.push_back(&cin_p);
    pdus.push_back(&deliv_cc_p);
    cid_p.encode_construct(ber::context_specific, 3, pdus);

    // ----------------------------------------------------------------------
    // Encode PSHeader
    // ----------------------------------------------------------------------

    // Encode the li-psDomainId
    ber::berpdu psdomainid_p;
    int psdomainid[] = {0, 4, 0, 2, 2, 5, 1, 13};
    psdomainid_p.encode_oid(ber::context_specific, 0, psdomainid, 7);

    // Encode LIID
    ber::berpdu liid_p;
    liid_p.encode_string(ber::context_specific, 1, liid);

    // Auth country code
    ber::berpdu authcountry_p;
    authcountry_p.encode_string(ber::context_specific, 2, country);

    // Encode Sequence
    ber::berpdu seq_p;
    seq_p.encode_int(ber::context_specific, 4, seq);

    // Encode the time.
    ber::berpdu tm_p;
    tm_p.encode_string(ber::context_specific, 5, tms);

    // Encode interceptionPointID
    ber::berpdu intpt_p;
    intpt_p.encode_string(ber::context_specific, 6, intpt);
    pdus.clear();
    pdus.push_back(&psdomainid_p);
    pdus.push_back(&liid_p);
    pdus.push_back(&authcountry_p);
    pdus.push_back(&cid_p);
    pdus.push_back(&seq_p);
    pdus.push_back(&tm_p);
    pdus.push_back(&intpt_p);
    psheader_p.encode_construct(ber::context_specific, 1, pdus);

}

void sender::encode_ipiri(ber::berpdu& ipiri_p,
			  const std::string& username,
			  int ipversion,
			  int accessevent)
{

    // ----------------------------------------------------------------------
    // Encode IPIRI
    // ----------------------------------------------------------------------

    // Access event type
    ber::berpdu accesseventtype_p;
    accesseventtype_p.encode_int(ber::context_specific, 0, accessevent);

    // Target user name
    ber::berpdu targetusername_p;
    targetusername_p.encode_string(ber::context_specific, 1, username);

    // Broadband internet
    ber::berpdu internetaccess_p;
    internetaccess_p.encode_int(ber::context_specific, 2, 1);

    // IP version: 1 = IPv4, 2 = IPv6, 3 = IPv4 and IPv6
    ber::berpdu ipversion_p;
    ipversion_p.encode_int(ber::context_specific, 3, ipversion);

    // IPIRIContents
    ber::berpdu ipiricontents_p;
    std::list<ber::berpdu*> pdus;
    pdus.push_back(&accesseventtype_p);
    pdus.push_back(&targetusername_p);
    pdus.push_back(&internetaccess_p);
    pdus.push_back(&ipversion_p);
    ipiricontents_p.encode_construct(ber::context_specific, 1, pdus);

    // iPIRIObjId
    ber::berpdu ipiriobjid_p;
    int ipiriobjid[] = {5, 3, 9, 1};
    ipiriobjid_p.encode_oid(ber::context_specific, 0, ipiriobjid, 4);

    // IPIRI
    pdus.clear();
    pdus.push_back(&ipiriobjid_p);
    pdus.push_back(&ipiricontents_p);
    ipiri_p.encode_construct(ber::context_specific, 2, pdus);

}

void sender::ia_acct_start_request(const std::string& liid,
				   const std::string& oper,
				   long seq, long cin,
				   const std::string& country,
				   const std::string& net_element,
				   const std::string& int_pt,
				   const std::string& username)
{

    std::list<ber::berpdu*> pdus;

    // ----------------------------------------------------------------------
    // Encode IPIRI
    // ----------------------------------------------------------------------

    // IPIRI, IP version 3 means IPv4 and IPv6.
    // Access event type = accessAttempt(0).
    ber::berpdu ipiri_p;
    encode_ipiri(ipiri_p, username, 3, 0);

    // ----------------------------------------------------------------------
    // Encode IRIPayload
    // ----------------------------------------------------------------------

    // IRIContents
    ber::berpdu iri_contents_p;
    pdus.clear();
    pdus.push_back(&ipiri_p);
    iri_contents_p.encode_construct(ber::context_specific, 2, pdus);

    // IRI-type = Report(4)
    ber::berpdu iri_type_p;
    iri_type_p.encode_int(ber::context_specific, 0, 4);

    // Sequence of IRIPayload
    ber::berpdu iri_payload_p;
    pdus.clear();
    pdus.push_back(&iri_type_p);
    pdus.push_back(&iri_contents_p);
    iri_payload_p.encode_construct(ber::universal, 16, pdus);

    // Sequence of IRIPayload
    ber::berpdu seq_of_iri_p;
    pdus.clear();
    pdus.push_back(&iri_payload_p);
    seq_of_iri_p.encode_construct(ber::context_specific, 0, pdus);

    // ----------------------------------------------------------------------
    // Encode Payload
    // ----------------------------------------------------------------------

    ber::berpdu payload_p;
    pdus.clear();
    pdus.push_back(&seq_of_iri_p);
    payload_p.encode_construct(ber::context_specific, 2, pdus);

    // ----------------------------------------------------------------------
    // Encode PSHeader
    // ----------------------------------------------------------------------

    ber::berpdu psheader_p;
    encode_psheader(psheader_p, liid, oper, seq, cin, country, net_element,
		    int_pt);

    // ----------------------------------------------------------------------
    // PS-PDU
    // ----------------------------------------------------------------------
    ber::berpdu pspdu_p;
    pdus.clear();
    pdus.push_back(&psheader_p);
    pdus.push_back(&payload_p);
    pspdu_p.encode_construct(ber::universal, 16, pdus);

    int ret = sock.write(pspdu_p.data);
    if (ret <= 0)
	throw std::runtime_error("Write failed.");

}

void sender::ia_acct_start_response(const std::string& liid,
				    const std::string& oper,
				    long seq, long cin,
				    const std::string& country,
				    const std::string& net_element,
				    const std::string& int_pt,
				    const std::string& username)
{

    std::list<ber::berpdu*> pdus;

    // ----------------------------------------------------------------------
    // Encode IPIRI
    // ----------------------------------------------------------------------

    // IPIRI, IP version 3 means IPv4 and IPv6.
    // Access event type = accessAccept(1).
    ber::berpdu ipiri_p;
    encode_ipiri(ipiri_p, username, 3, 1);

    // ----------------------------------------------------------------------
    // Encode IRIPayload
    // ----------------------------------------------------------------------

    // IRIContents
    ber::berpdu iri_contents_p;
    pdus.clear();
    pdus.push_back(&ipiri_p);
    iri_contents_p.encode_construct(ber::context_specific, 2, pdus);

    // IRI-type = Begin(1)
    ber::berpdu iri_type_p;
    iri_type_p.encode_int(ber::context_specific, 0, 1);

    // Sequence of IRIPayload
    ber::berpdu iri_payload_p;
    pdus.clear();
    pdus.push_back(&iri_type_p);
    pdus.push_back(&iri_contents_p);
    iri_payload_p.encode_construct(ber::universal, 16, pdus);

    // Sequence of IRIPayload
    ber::berpdu seq_of_iri_p;
    pdus.clear();
    pdus.push_back(&iri_payload_p);
    seq_of_iri_p.encode_construct(ber::context_specific, 0, pdus);

    // ----------------------------------------------------------------------
    // Encode Payload
    // ----------------------------------------------------------------------

    ber::berpdu payload_p;
    pdus.clear();
    pdus.push_back(&seq_of_iri_p);
    payload_p.encode_construct(ber::context_specific, 2, pdus);

    // ----------------------------------------------------------------------
    // Encode PSHeader
    // ----------------------------------------------------------------------

    ber::berpdu psheader_p;
    encode_psheader(psheader_p, liid, oper, seq, cin, country, net_element,
		    int_pt);

    // ----------------------------------------------------------------------
    // PS-PDU
    // ----------------------------------------------------------------------
    ber::berpdu pspdu_p;
    pdus.clear();
    pdus.push_back(&psheader_p);
    pdus.push_back(&payload_p);
    pspdu_p.encode_construct(ber::universal, 16, pdus);

    // Send PDU
    int ret = sock.write(pspdu_p.data);
    if (ret <= 0)
	throw std::runtime_error("Write failed.");

}

void sender::ia_acct_stop(const std::string& liid,
			  const std::string& oper,
			  long seq, long cin,
			  const std::string& country,
			  const std::string& net_element,
			  const std::string& int_pt,
			  const std::string& username)
{

    std::list<ber::berpdu*> pdus;

    // ----------------------------------------------------------------------
    // Encode IPIRI
    // ----------------------------------------------------------------------

    // IPIRI, IP version 3 means IPv4 and IPv6.
    // Access event type = accessEnd(8).
    ber::berpdu ipiri_p;
    encode_ipiri(ipiri_p, username, 3, 8);

    // ----------------------------------------------------------------------
    // Encode IRIPayload
    // ----------------------------------------------------------------------

    // IRIContents
    ber::berpdu iri_contents_p;
    pdus.clear();
    pdus.push_back(&ipiri_p);
    iri_contents_p.encode_construct(ber::context_specific, 2, pdus);

    // IRI-type = End(2)
    ber::berpdu iri_type_p;
    iri_type_p.encode_int(ber::context_specific, 0, 2);

    // Sequence of IRIPayload
    ber::berpdu iri_payload_p;
    pdus.clear();
    pdus.push_back(&iri_type_p);
    pdus.push_back(&iri_contents_p);
    iri_payload_p.encode_construct(ber::universal, 16, pdus);

    // Sequence of IRIPayload
    ber::berpdu seq_of_iri_p;
    pdus.clear();
    pdus.push_back(&iri_payload_p);
    seq_of_iri_p.encode_construct(ber::context_specific, 0, pdus);

    // ----------------------------------------------------------------------
    // Encode Payload
    // ----------------------------------------------------------------------

    ber::berpdu payload_p;
    pdus.clear();
    pdus.push_back(&seq_of_iri_p);
    payload_p.encode_construct(ber::context_specific, 2, pdus);

    // ----------------------------------------------------------------------
    // Encode PSHeader
    // ----------------------------------------------------------------------

    ber::berpdu psheader_p;
    encode_psheader(psheader_p, liid, oper, seq, cin, country, net_element,
		    int_pt);

    // ----------------------------------------------------------------------
    // PS-PDU
    // ----------------------------------------------------------------------
    ber::berpdu pspdu_p;
    pdus.clear();
    pdus.push_back(&psheader_p);
    pdus.push_back(&payload_p);
    pspdu_p.encode_construct(ber::universal, 16, pdus);

    // Send PDU
    int ret = sock.write(pspdu_p.data);
    if (ret <= 0)
	throw std::runtime_error("Write failed.");

}

void sender::send_ip(const std::string& liid,
		     const std::string& oper,
		     long seq, long cin,
		     const std::vector<unsigned char>& packet,
		     const std::string& country,
		     const std::string& net_element,
		     const std::string& int_pt)
{

    // ----------------------------------------------------------------------
    // Encode IPCC
    // ----------------------------------------------------------------------

    // Packet
    ber::berpdu packet_p;
    packet_p.encode_string(ber::context_specific, 0, packet);

    // IPCCContents
    ber::berpdu ipcccontents_p;
    std::list<ber::berpdu*> pdus;
    pdus.push_back(&packet_p);
    ipcccontents_p.encode_construct(ber::context_specific, 1, pdus);

    // iPCCObjId
    ber::berpdu ipccobjid_p;
    int ipccobjid[] = {5, 3, 9, 2};
    ipccobjid_p.encode_oid(ber::context_specific, 0, ipccobjid, 4);

    // IPCCContents
    ber::berpdu ipcc_p;
    pdus.clear();
    pdus.push_back(&ipccobjid_p);
    pdus.push_back(&ipcccontents_p);
    ipcc_p.encode_construct(ber::context_specific, 2, pdus);


    // ----------------------------------------------------------------------
    // Encode CCPayload
    // ----------------------------------------------------------------------

    // CCContents
    ber::berpdu cccontents_p;
    pdus.clear();
    pdus.push_back(&ipcc_p);
    cccontents_p.encode_construct(ber::context_specific, 2, pdus);

    // Sequence
    ber::berpdu ccpayload_p;
    pdus.clear();
    pdus.push_back(&cccontents_p);
    ccpayload_p.encode_construct(ber::universal, 16, pdus);

    // Sequence of CCPayload
    ber::berpdu seq_of_cc_p;
    pdus.clear();
    pdus.push_back(&ccpayload_p);
    seq_of_cc_p.encode_construct(ber::context_specific, 1, pdus);

    // ----------------------------------------------------------------------
    // Encode Payload
    // ----------------------------------------------------------------------

    ber::berpdu payload_p;
    pdus.clear();
    pdus.push_back(&seq_of_cc_p);
    payload_p.encode_construct(ber::context_specific, 2, pdus);

    // ----------------------------------------------------------------------
    // Encode PSHeader
    // ----------------------------------------------------------------------

    ber::berpdu psheader_p;
    encode_psheader(psheader_p, liid, oper, seq, cin, country, net_element,
		    int_pt);

    // ----------------------------------------------------------------------
    // PS-PDU
    // ----------------------------------------------------------------------
    ber::berpdu pspdu_p;
    pdus.clear();
    pdus.push_back(&psheader_p);
    pdus.push_back(&payload_p);
    pspdu_p.encode_construct(ber::universal, 16, pdus);

    // Send PDU
    int ret = sock.write(pspdu_p.data);
    if (ret <= 0)
	throw std::runtime_error("Write failed.");

}

// Called when target "connects" to the IP access network.
void mux::target_connect(const std::string& liid,     // LIID
			 const std::string& oper,     // Operator ID
			 const std::string& country,  // Country e.g. GB
			 const std::string& net_elt,  // Net element
			 const std::string& int_pt,   // Intercept pt.
			 const std::string& username) // User ID
{

    // Initialise sequence and CIN.
    seq[liid] = 0;
    cin[liid] = next_cin++;

    // Describes connetion request.
    transport.ia_acct_start_request(liid, oper, seq[liid]++, cin[liid],
				    country, net_elt, int_pt, username);

    // Describes connection response.
    transport.ia_acct_start_response(liid, oper, seq[liid]++, cin[liid],
				    country, net_elt, int_pt, username);

}

// Called when a target disconnects.
void mux::target_disconnect(const std::string& liid,     // LIID
			    const std::string& oper,     // Operator ID
			    const std::string& country,  // Country
			    const std::string& net_elt,  // Net element
			    const std::string& int_pt,   // Intercept
			    const std::string& username) // User ID
{

    // Bail if we haven't connected this LIID.
    if (seq.find(liid) == seq.end())
	throw std::runtime_error("LIID is not connected.");

    // Describes a connection stop.
    transport.ia_acct_stop(liid, oper, seq[liid]++, cin[liid],
			   country, net_elt, int_pt, username);

    // Clear the CIN & sequence information.
    cin.erase(liid);
    seq.erase(liid);

}

// Called when a target IP packet is observed.
void mux::target_ip(const std::string& liid,               // LIID
		    const std::vector<unsigned char>& pdu, // Packet
		    const std::string& oper,               // Operator ID
		    const std::string& country,            // Country
		    const std::string& net_elt,            // Net element
		    const std::string& int_pt)             // Intercept
{


    // Bail if we haven't connected this LIID.
    if (seq.find(liid) == seq.end())
	throw std::runtime_error("LIID is not connected.");

    // Describes the IP packet.
    transport.send_ip(liid, oper, seq[liid]++, cin[liid],
		      pdu, country, net_elt, int_pt);


}

void receiver::run()
{

    svr.bind(port);
    svr.listen();

    while (running) {

	bool activ = svr.poll(1.0);

	if (activ) {

	    tcpip::tcp_socket cn;
	    svr.accept(cn);

	    connection* c = new connection(cn, p, *this);
	    c->start();

	}

	close_me_lock.lock();

	while (!close_mes.empty()) {
	    close_mes.front()->join();
	    delete close_mes.front();
	    close_mes.pop();
	}
	close_me_lock.unlock();

    }

}

void connection::run()
{

    try {

	while (1) {

	    ber::berpdu pdu;

	    bool got = pdu.read_pdu(s);

	    // Error or end of stream.
	    if (!got) break;

	    // Decode header and payloads.
	    ber::berpdu& hdr_p = pdu.get_element(1);
	    ber::berpdu& liid_p = hdr_p.get_element(1);
	    ber::berpdu& pay_p = pdu.get_element(2);

	    std::list<ber::berpdu> payload_pdus;
	    pay_p.decode_construct(payload_pdus);

	    // Do LIID
	    std::string liid;
	    liid_p.decode_string(liid);

	    // Study payload
	    for(std::list<ber::berpdu>::iterator it = payload_pdus.begin();
		it != payload_pdus.end();
		it++) {

		if (it->get_tag() == 1) {

		    std::list<ber::berpdu> seq_pdus;
		    it->decode_construct(seq_pdus);

		    for(std::list<ber::berpdu>::iterator it2 = seq_pdus.begin();
			it2 != seq_pdus.end();
			it2++) {

			ber::berpdu& ccc_p = it2->get_element(2);

			ber::berpdu& ipcc_p = ccc_p.get_element(2);

			ber::berpdu& ipccontents_p = ipcc_p.get_element(1);

			ber::berpdu& packet_p = ipccontents_p.get_element(0);

			std::vector<unsigned char> pkt;
			
			packet_p.decode_vector(pkt);

			p(liid, pkt.begin(), pkt.end());

		    }

		}

	    }

	}
	
    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

    s.close();

    r.close_me(this);

}

void receiver::close_me(connection* c)
{
    close_me_lock.lock();
    close_mes.push(c);
    close_me_lock.unlock();
}



/****************************************************************************


   oMoMoMoMMo
   " "MMM"""
      oMM                o
      oMM               oM"      oo       oo
      oMM               MM"     "MM"    "MMMo     oMMMMMMMMMMMo    oo o o o
      oMM               oMM     oMMo    MMM"Mo      " " "MM "    "MMMMMMMMM
    oooMMoooooo         oMo      MM     MM "MMo         MMo      "MM
    "M"M"M"M"M""       oMMMooMoMMMM"   oMMo oMMoo       oM"      "MMo  o
                       oMMM""""""MMo   MMMMMMMMMoo      oMM      "MMMMMMMo
                       oMo      "MM   oMM       MMM     oMM      "MM
    ooM                "Mo      "Mo   oMM"       MMo    oMM      "MM
   MMM"MMo             MM"      "MM   oMM        MMo    oMM     "MMo
  oMM  "MM   oo        """      """   oMM                       oMMoMMoMMoMo
  oMMMoMMMM "Mo  oM                             o                """""""""
  "MM"""""  "MMoMM"   MoMoo           o         M   MMM
  MMMoo     "MMM"   oMMM"MMo   ooMo  "M" ooM  MMMM  MMo     o
   ""M""    "MMM   oMMMMMM"  MMM" "  MMM MMM"  MM   MMoo   "M
             MMM   oMM  "    MMM      "MMMMM"  MM  "MMMMMM  ooo   oooo   ooM o
             "      "MMMoo   MMM         "MMo  MM   MMMoMMo "Mo "MM"MMM oMM MMo
                       ""    "M           MMo  MM  "MM" MMo "MM oMM oMM "Mo MMM
                                   oMooMMMM"   "    """  M  "MMo Mo "MM "MMMMMo
      ooo oo    Mo                """"""""                    "          " ""Mo
   oMMMM"MMMo o"MM                                                          MM"
          MM   "MM                                        oMMMMMMMMoMoo    oMMM
         MMMo  "MMMMMMMMo    ooo                "Mo         " " " """"MMMMMM""
     MMMMMMMo   "Mo"o"oMMo oMM"MMoo  MMo        MMo
   MMM"  "MM    MMMMMMM""  MM"  MMM "MM   oMo oMMMMoMMoM
   ""MMMMMMM               MMooo"MM "MM  MMM   "MM""""""
     " " "                  "M"M"M  "MMMMMM     MM"
                                       "       "MM o o
                                                MMMMMM"
                                                  "

                oooooooo       ooooooooooo oooooo   oooooo       oooooo
                oMMMMMMM      MMMMMMMMMMM" MMMMMMo  oMMMMM       MMMMM"
                oMMMMMM      MMMM " " "MM  "MMMMMM   MMMM         "MMM
               oMMMMMMMo     MMMoo o o     MMMMMMMM  MMM          MMMM
              MMMM  MMMM     MMMMMMMMMMo   MMM"MMMM MMMM          MMM"
            oMMMMMoMMMMMM     """""""MMM   MMM  MMMMMMM"          MMM
           MMMMMMMMMMMMMMo   o      MMMM  MMMM  MMMMMMM          MMMM
         oMMMMM      oMMMMooMMMMooMoMMM  oMMMM   MMMMMMo   oMoo oMMMM
        "MMMMM"     oMMMMMMMMMMMMMMMMM" "MMMMM   "MMMMM"   MMM oMMMMM


****************************************************************************/


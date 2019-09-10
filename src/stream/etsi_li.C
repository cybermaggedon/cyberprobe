
#include <fstream>

#include <cyberprobe/protocol/pdu.h>

#include <cyberprobe/stream/etsi_li.h>
#include <cyberprobe/stream/ber.h>

#include <sys/time.h>
#include <string.h>

// Support for a simple usage of ETSI LI protocol, defined in ETSI TS 102 232.

using namespace cyberprobe::etsi_li;
using namespace cyberprobe::stream;
using namespace cyberprobe::protocol;

// The next CIN which will be used.
uint32_t mux::next_cin = 0;

// Encodes the ETSI LI PS PDU PSHeader construct.
void sender::encode_psheader(ber::berpdu& psheader_p,
                             timeval tv,
			     const std::string& liid,
			     const std::string& oper,
			     uint32_t seq, uint32_t cin,
			     const std::string& country,
			     const std::string& net_element,
			     const std::string& intpt)
{

    // Create a time string, GeneralizedTime.
    char tms[128];
    {
        // If we've been passed no specific time then use 'now'
        if (tv.tv_sec == 0) {
	    gettimeofday(&tv, 0);
        }

	struct tm res;
	struct tm* ts = gmtime_r(&tv.tv_sec, &res);
	if (ts == 0)
	    throw std::runtime_error("gmtime_r failed");

	// Convert time in seconds into into year, month... seconds.
	int ret = strftime(tms, 128, "%Y%m%d%H%M%S", ts);
	if (ret < 0)
	    throw std::runtime_error("Failed to format time string (strftime)");

	// Append milliseconds and Z for GMT.
	sprintf(tms + strlen(tms), ".%03dZ", int(tv.tv_usec / 1000));

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
    if (net_element != "")
	netelt_p.encode_string(ber::context_specific, 1, net_element);

    // NetworkIdentifier
    ber::berpdu neid_p;
    pdus.clear();
    pdus.push_back(&operid_p);
    if (net_element != "")
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
    if (country != "")
	deliv_cc_p.encode_string(ber::context_specific, 2, country);

    // Encode CID
    ber::berpdu cid_p;
    pdus.clear();
    pdus.push_back(&neid_p);
    pdus.push_back(&cin_p);
    if (country != "")
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
    if (country != "")
	authcountry_p.encode_string(ber::context_specific, 2, country);

    // Encode Sequence
    ber::berpdu seq_p;
    seq_p.encode_int(ber::context_specific, 4, seq);

    // Encode the time.
    ber::berpdu tm_p;
    tm_p.encode_string(ber::context_specific, 5, tms);

    // Encode interceptionPointID
    ber::berpdu intpt_p;
    if (intpt != "")
	intpt_p.encode_string(ber::context_specific, 6, intpt);

    pdus.clear();
    pdus.push_back(&psdomainid_p);
    pdus.push_back(&liid_p);
    if (country != "")
	pdus.push_back(&authcountry_p);
    pdus.push_back(&cid_p);
    pdus.push_back(&seq_p);
    pdus.push_back(&tm_p);
    if (intpt != "")
	pdus.push_back(&intpt_p);
    psheader_p.encode_construct(ber::context_specific, 1, pdus);

}

void sender::encode_ipiri(ber::berpdu& ipiri_p,
			  const std::string& username,
			  const tcpip::address* address,
			  int ipversion,
			  int accessevent)
{

    // ----------------------------------------------------------------------
    // Encode IPaddress
    // ----------------------------------------------------------------------

    std::list<ber::berpdu*> pdus;
    ber::berpdu ipaddress_p;

    if (address != 0) {

	// Binary address
	ber::berpdu binary_p;
	binary_p.encode_string(ber::context_specific, 1, address->addr.begin(),
			       address->addr.end());

	// IPtype
	ber::berpdu iptype_p;
	if (address->universe == address->ipv4)
	    iptype_p.encode_int(ber::context_specific, 1, 0); // IPv4 = 0
	else
	    iptype_p.encode_int(ber::context_specific, 1, 1); // IPv6 = 1

	// IPvalue
	ber::berpdu ipvalue_p;
	pdus.clear();
	pdus.push_back(&binary_p);
	ipvalue_p.encode_construct(ber::context_specific, 2, pdus);

	// IPAddress
	pdus.clear();
	pdus.push_back(&iptype_p);
	pdus.push_back(&ipvalue_p);
	ipaddress_p.encode_construct(ber::context_specific, 4, pdus);

    }

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
    pdus.clear();
    pdus.push_back(&accesseventtype_p);
    pdus.push_back(&targetusername_p);
    pdus.push_back(&internetaccess_p);
    pdus.push_back(&ipversion_p);
    if (address != 0)
	pdus.push_back(&ipaddress_p);
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
				   uint32_t seq, uint32_t cin,
				   const std::string& oper,
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
    encode_ipiri(ipiri_p, username, 0, 3, 0);

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
    // time for connection request will be taken as 'now'
    timeval tv = {0};
    encode_psheader(psheader_p, tv, liid, oper, seq, cin, country, net_element,
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
				    const tcpip::address& target_addr,
				    uint32_t seq, uint32_t cin,
				    const std::string& oper,
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
    encode_ipiri(ipiri_p, username, &target_addr, 3, 1);

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
    // time for connection response will be taken as 'now'
    timeval tv = {0};
    encode_psheader(psheader_p, tv, liid, oper, seq, cin, country, net_element,
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
			  uint32_t seq, uint32_t cin,
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
    encode_ipiri(ipiri_p, username, 0, 3, 8);

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
    // time for disconnect will be taken as 'now'
    timeval tv = {0};
    encode_psheader(psheader_p, tv, liid, oper, seq, cin, country, net_element,
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

// Transmit an IP packet
void sender::send_ip(timeval tv,
                     const std::string& liid,
		     const std::string& oper,
		     uint32_t seq, uint32_t cin,
		     const std::vector<unsigned char>& packet,
		     const std::string& country,
		     const std::string& net_element,
		     const std::string& int_pt,
                     direction dir)
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

    // Direction
    ber::berpdu payload_direction_p;
    int direction;
    if (dir == direction::FROM_TARGET)
        direction = 0;
    else if (dir == direction::TO_TARGET)
        direction = 1;
    else
        direction = 2;
        
    payload_direction_p.encode_int(ber::context_specific, 0, direction);
    pdus.clear();

    // CCContents
    ber::berpdu cccontents_p;
    pdus.clear();
    pdus.push_back(&ipcc_p);
    cccontents_p.encode_construct(ber::context_specific, 2, pdus);

    // Sequence
    ber::berpdu ccpayload_p;
    pdus.clear();
    pdus.push_back(&payload_direction_p);
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
    encode_psheader(psheader_p, tv, liid, oper, seq, cin, country, net_element,
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
			 const tcpip::address& target_addr, // Target IP addr
			 const std::string& oper,     // Operator ID
			 const std::string& country,  // Country e.g. GB
			 const std::string& net_elt,  // Net element
			 const std::string& int_pt,   // Intercept pt.
			 const std::string& username) // User ID
{

    // Initialise sequence and CIN.
    iri_seq[liid] = 0;
    cc_seq[liid] = 0;

    cin[liid] = next_cin++;

    // Describes connection request.
    transport.ia_acct_start_request(liid, iri_seq[liid]++, cin[liid], oper,
				    country, net_elt, int_pt, username);

    // Describes connection response.
    transport.ia_acct_start_response(liid, target_addr, iri_seq[liid]++,
				     cin[liid], oper, country, net_elt,
				     int_pt, username);

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
    if (iri_seq.find(liid) == iri_seq.end()) {
	// This isn't right, but silently ignore.
	return;
    }

    // Describes a connection stop.
    transport.ia_acct_stop(liid, oper, iri_seq[liid]++, cin[liid],
			   country, net_elt, int_pt, username);

    // Clear the CIN & sequence information.
    cin.erase(liid);
    iri_seq.erase(liid);
    cc_seq.erase(liid);

}

// Called when a target IP packet is observed.
void mux::target_ip(timeval tv,                            // Time of capture
                    const std::string& liid,               // LIID
		    const std::vector<unsigned char>& pdu, // Packet
		    const std::string& oper,               // Operator ID
		    const std::string& country,            // Country
		    const std::string& net_elt,            // Net element
		    const std::string& int_pt,             // Intercept
                    direction dir)                         // To/from target
{


    // Bail if we haven't connected this LIID.
    if (cc_seq.find(liid) == cc_seq.end()) {
	// This isn't right, but cope with it anyway.
	iri_seq[liid] = 0;
	cc_seq[liid] = 0;
	cin[liid] = next_cin++;
    }

    // Describes the IP packet.
    transport.send_ip(tv, liid, oper, cc_seq[liid]++, cin[liid],
		      pdu, country, net_elt, int_pt, dir);


}

// ETSI LI master receiver body, handles connections.
void receiver::run()
{

    try {

	svr->listen();

	while (running) {

	    bool activ = svr->poll(1.0);

	    if (activ) {

		std::shared_ptr<tcpip::stream_socket> cn;

		try {
		    cn = svr->accept();
		} catch (...) {
		    continue;
		}

		connection* c = new connection(cn, p, *this);

		c->start();

	    }

	    std::lock_guard<std::mutex> lock(close_me_mutex);

	    while (!close_mes.empty()) {
		close_mes.front()->join();
		delete close_mes.front();
		close_mes.pop();
	    }

	}

    } catch (std::exception& e) {

	std::cerr << "Exception: " << e.what() << std::endl;
	return;

    }

}

// ETSI LI connection body, handles a single connection.
void connection::run()
{

    try {

	while (1) {

	    ber::berpdu pdu;

	    bool got = pdu.read_pdu(*s);

	    // Error or end of stream.
	    if (!got) break;

	    // Decode header and payloads.
	    ber::berpdu& hdr_p = pdu.get_element(1);
	    ber::berpdu& liid_p = hdr_p.get_element(1);
	    ber::berpdu& pay_p = pdu.get_element(2);

	    // Packet timestamp
	    struct timeval tv;

	    try {

		// Get time as string.
		// Possible formats are:
		//
		//   YYYYMMDDHH[MM[SS[.fff]]]
		//   YYYYMMDDHH[MM[SS[.fff]]]Z
		//   YYYYMMDDHH[MM[SS[.fff]]]+-HHMM

		ber::berpdu& time_p = hdr_p.get_element(5);
		std::string tm;
		time_p.decode_string(tm);

		int Y, M, D, h, m, s, ms=0;
		unsigned char gmt = 0;

		// Parse time string.
		int ret = sscanf(tm.c_str(), "%04d%02d%02d%02d%02d%02d.%03d%c",
				 &Y, &M, &D, &h, &m, &s, &ms, &gmt);

		// Need at least 6 values to make a timestring.  If
		// we don't get them, bail.
		// This jumps to the catch below...
		if (ret < 6)
		    throw std::runtime_error("Couldn't parse time");

		// Got enough information to construct a timestring.

		// Note that we assume GMT / UCT / Zulu time.  There is a
		// local-time case in GeneralizedTime.

		struct tm t;
		t.tm_year = Y - 1900; // Year since 1900
		t.tm_mon = M - 1;     // 0-11
		t.tm_mday = D;        // 1-31
		t.tm_hour = h;        // 0-23
		t.tm_min = m;         // 0-59
		t.tm_sec = (int)s;    // 0-61 (0-60 in C++11)

		tv.tv_sec = timegm(&t);
		tv.tv_usec = ms * 1000;  // Turn milliseconds into seconds.

	    } catch (...) {
		// Time value defaults to 'now' if there's no timestamp in the
		// data.
		gettimeofday(&tv, 0);
	    }

	    std::string network;
	    try {
		ber::berpdu& cid_p = hdr_p.get_element(3);
		ber::berpdu& nid_p = cid_p.get_element(0);
		ber::berpdu& neid_p = nid_p.get_element(1);
		neid_p.decode_string(network);
	    } catch (...) {
		// Missing NEID, just ignore.
	    }

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

		    // CC case

		    std::list<ber::berpdu> seq_pdus;
		    it->decode_construct(seq_pdus);

		    for(std::list<ber::berpdu>::iterator it2 = seq_pdus.begin();
			it2 != seq_pdus.end();
			it2++) {

                        // Decode direction.
                        direction dir = NOT_KNOWN;
                        try {
                            ber::berpdu& dir_p = it2->get_element(0);
                            int direc = dir_p.decode_int();
                            if (direc == 0)
                                dir = direction::FROM_TARGET;
                            else if (direc == 1)
                                dir = direction::TO_TARGET;
                        } catch (...) {
                        }

			ber::berpdu& ccc_p = it2->get_element(2);
			ber::berpdu& ipcc_p = ccc_p.get_element(2);
			ber::berpdu& ipccontents_p = ipcc_p.get_element(1);
			ber::berpdu& packet_p = ipccontents_p.get_element(0);

			std::vector<unsigned char> pkt;

			packet_p.decode_vector(pkt);

			p(liid, network,
                          pdu_slice(pkt.begin(), pkt.end(), tv, dir));

		    }

		} else if (it->get_tag() == 0) {

		    try {

			std::vector<unsigned char> ip_addr;
			long iritype;
			int accesseventtype = -1;

			// IRI case
			std::list<ber::berpdu> seq_pdus;
			it->decode_construct(seq_pdus);

			for(std::list<ber::berpdu>::iterator it2 =
				seq_pdus.begin();
			    it2 != seq_pdus.end();
			    it2++) {

			    ber::berpdu& iritype_p = it2->get_element(0);
			    iritype = iritype_p.decode_int();

			    ber::berpdu& iricontents_p = it2->get_element(2);
			    ber::berpdu& ipiri_p = iricontents_p.get_element(2);

			    ber::berpdu& ipiricontents_p =
				ipiri_p.get_element(1);

			    ber::berpdu& accesseventtype_p =
				ipiricontents_p.get_element(0);

			    accesseventtype = accesseventtype_p.decode_int();

			    // Get ready to decode IP address.
			    try {

				ber::berpdu& targetipaddress_p =
				    ipiricontents_p.get_element(4);

				ber::berpdu& ipvalue_p =
				    targetipaddress_p.get_element(2);

				ber::berpdu& ipbinary_p =
				    ipvalue_p.get_element(1);

				ipbinary_p.decode_vector(ip_addr);

			    } catch (...) {
				// Oh well, no IP address.
			    }

			    // Process IRI here.

/*
  std::cerr << "IRI type = " << iritype << std::endl;
  std::cerr << "AET = " << accesseventtype
  << std::endl;
  std::cerr << "Liid = " << liid << std::endl;;
  std::cerr << "Addr vec size = "
  << ip_addr.size()
  << std::endl;
  std::cerr << std::endl;
*/

			    if (iritype == 1 && accesseventtype == 1 &&
				ip_addr.size() != 0) {

				// Target up and we have an address.
				if (ip_addr.size() == 4) {
				    tcpip::ip4_address a;
				    a.addr.assign(ip_addr.begin(),
						  ip_addr.end());
				    p.target_up(liid, network, a, tv);
				}

				if (ip_addr.size() == 16) {
				    tcpip::ip6_address a;
				    a.addr.assign(ip_addr.begin(),
						  ip_addr.end());
				    p.target_up(liid, network, a, tv);
				}

			    }

			    if (iritype == 2) {
				p.target_down(liid, network, tv);
			    }

			}

		    } catch (std::exception& e) {
			// Didn't like the IRI data, so what, just ignore.
//			std::cerr << e.what() << std::endl;
		    }

		}

	    }

	}

    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

    s->close();

    r.close_me(this);

}

void receiver::close_me(connection* c)
{
    std::lock_guard<std::mutex> lock(close_me_mutex);
    close_mes.push(c);
}


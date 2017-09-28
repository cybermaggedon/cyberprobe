
#include <fstream>

#include <cybermon/etsi_li.h>
#include <cybermon/ber.h>

// Support for a simple usage of ETSI LI protocol, defined in ETSI TS 102 232.

using namespace cybermon::etsi_li;

// The next CIN which will be used.
uint32_t mux::next_cin = 0;

// Encodes the ETSI LI PS PDU PSHeader construct.
void sender::encode_psheader(ber::berpdu& psheader_p,
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
	struct timeval now;
	gettimeofday(&now, 0);
	struct tm res;
	struct tm* ts = gmtime_r(&now.tv_sec, &res);

	// Convert time in seconds into into year, month... seconds. 
	strftime(tms, 128, "%Y%m%d%H%M%S", ts);

	// Append milliseconds and Z for GMT.
	sprintf(tms + strlen(tms), ".%03dZ", now.tv_usec / 1000);

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

// Transmit an IP packet
void sender::send_ip(const std::string& liid,
		     const std::string& oper,
		     uint32_t seq, uint32_t cin,
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

    // Describes connetion request.
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
void mux::target_ip(const std::string& liid,               // LIID
		    const std::vector<unsigned char>& pdu, // Packet
		    const std::string& oper,               // Operator ID
		    const std::string& country,            // Country
		    const std::string& net_elt,            // Net element
		    const std::string& int_pt)             // Intercept
{


    // Bail if we haven't connected this LIID.
    if (cc_seq.find(liid) == cc_seq.end()) {
	// This isn't right, but cope with it anyway.
	iri_seq[liid] = 0;
	cc_seq[liid] = 0;
	cin[liid] = next_cin++;
    }

    // Describes the IP packet.
    transport.send_ip(liid, oper, cc_seq[liid]++, cin[liid],
		      pdu, country, net_elt, int_pt);


}

// ETSI LI master receiver body, handles connections.
void receiver::run()
{

    try {

	svr->listen();

	while (running) {

	    bool activ = svr->poll(1.0);

	    if (activ) {

		boost::shared_ptr<tcpip::stream_socket> cn;

		try {
		    cn = svr->accept();
		} catch (...) {
		    continue;
		}

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

	    struct timeval tv;

	    // Time value defaults to 'now' if there's no timestamp in the
	    // data.
	    gettimeofday(&tv, 0);

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

		std::cerr << tm << std::endl;
		    
		int Y, M, D, h, m, s, ms=0;
		unsigned char gmt = 0;

		// Parse time string.
		int ret = sscanf(tm.c_str(), "%04d%02d%02d%02d%02d%02d.%03d%c",
				 &Y, &M, &D, &h, &m, &s, &ms, &gmt);

		if (ret < 6)
		    // This jumps to the catch below...
		    throw std::runtime_error("Couldn't parse time");

		// Describe ignored cases.

		std::cerr << ret << std::endl;
		std::cerr << Y << " " << M << " " << D << " "
			  << h << " " << m << " " << s << "." << ms
			  << " " << (int) gmt << std::endl;

		struct tm t;
		t.tm_year = Y - 1900; // Year since 1900
		t.tm_mon = M - 1;     // 0-11
		t.tm_mday = D;        // 1-31
		t.tm_hour = h;        // 0-23
		t.tm_min = m;         // 0-59
		t.tm_sec = (int)s;    // 0-61 (0-60 in C++11)

		tv.tv_sec = timegm(&t);
		tv.tv_usec = ms * 1000;  // Turn milliseconds into seconds.
		
	    } catch (...) {}

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

			ber::berpdu& ccc_p = it2->get_element(2);
			ber::berpdu& ipcc_p = ccc_p.get_element(2);
			ber::berpdu& ipccontents_p = ipcc_p.get_element(1);
			ber::berpdu& packet_p = ipccontents_p.get_element(0);

			std::vector<unsigned char> pkt;
			
			packet_p.decode_vector(pkt);

			p(liid, pkt.begin(), pkt.end());

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
				    p.target_up(liid, a);
				}
			
				if (ip_addr.size() == 16) {
				    tcpip::ip6_address a;
				    a.addr.assign(ip_addr.begin(),
						  ip_addr.end());
				    p.target_up(liid, a);
				}

			    }
			    
			    if (iritype == 2) {
				p.target_down(liid);
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



/****************************************************************************

****************************************************************************
*** OVERVIEW
****************************************************************************

Simple monitor.  Takes ETSI streams from cyberprobe, and reports on various
occurances.

Usage:

    cyberprobe <port-number>

****************************************************************************/

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

class obs : public cybermon::engine {
private:
    cybermon::cybermon_lua cml;

public:

    obs(const std::string& path) : cml(path) {}

    // Connection-orientated.
    virtual void connection_up(const cybermon::context_ptr cp) {
	try {
	    cml.connection_up(*this, cp);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    virtual void connection_down(const cybermon::context_ptr cp) {
	try{
	    cml.connection_down(*this, cp);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    virtual void unrecognised_stream(const cybermon::context_ptr cp,
				     cybermon::pdu_iter s, 
				     cybermon::pdu_iter e) {
	try {
	    cml.unrecognised_stream(*this, cp, s, e);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    // Connection-less
    virtual void unrecognised_datagram(const cybermon::context_ptr cp,
			  cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
	    cml.unrecognised_datagram(*this, cp, s, e);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    virtual void icmp(const cybermon::context_ptr cp,
		      cybermon::pdu_iter s, cybermon::pdu_iter e) {
	try {
	    cml.icmp(*this, cp, s, e);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    // HTTP
    virtual void http_request(const cybermon::context_ptr cp,
			      const std::string& method,
			      const std::string& url,
			      const cybermon::observer::http_hdr_t& hdr,
			      cybermon::pdu_iter body_start,
			      cybermon::pdu_iter body_end) {
	try {
	    cml.http_request(*this, cp, method, url, hdr, body_start, body_end);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    virtual void http_response(const cybermon::context_ptr cp,
			       unsigned int code,
			       const std::string& status,
			       const cybermon::observer::http_hdr_t& hdr,
			       const std::string& url,
			       cybermon::pdu_iter body_start,
			       cybermon::pdu_iter body_end) {
	try {
	    cml.http_response(*this, cp, code, status, hdr, url, 
			      body_start, body_end);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    // SMTP
    virtual void smtp_command(const cybermon::context_ptr cp,
			      const std::string& command) {
	try {
	    cml.smtp_command(*this, cp, command);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    virtual void smtp_response(const cybermon::context_ptr cp,
			       int status,
			       const std::list<std::string>& text) {
	try {
	    cml.smtp_response(*this, cp, status, text);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    virtual void smtp_data(const cybermon::context_ptr cp,
			   const std::string& from,
			   const std::list<std::string>& to,
			   std::vector<unsigned char>::const_iterator s,
			   std::vector<unsigned char>::const_iterator e) {
	try {
	    cml.smtp_data(*this, cp, from, to, s, e);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    // FTP
    virtual void ftp_command(const cybermon::context_ptr cp,
			     const std::string& command) {
	try {
	    cml.ftp_command(*this, cp, command);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }
    
    virtual void ftp_response(const cybermon::context_ptr cp,
			      int status,
			      const std::list<std::string>& responses) {
	try {
	    cml.ftp_response(*this, cp, status, responses);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    // Trigger
    void trigger_up(const std::string& liid, const tcpip::address& a) {
	try {
	    cml.trigger_up(liid, a);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    void trigger_down(const std::string& liid) {
	try {
	    cml.trigger_down(liid);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

    // DNS
    virtual void dns_message(const cybermon::context_ptr cp,
			     const cybermon::dns_header hdr,
			     const std::list<cybermon::dns_query> queries,
			     const std::list<cybermon::dns_rr> answers,
			     const std::list<cybermon::dns_rr> authorities,
			     const std::list<cybermon::dns_rr> additional) {
	try {
	    cml.dns_message(*this, cp, hdr, queries, answers, authorities,
			    additional);
	} catch (std::exception& e) {
	    std::cerr << "Error: " << e.what() << std::endl;
	}
    }

};

// Monitor class, implements the monitor interface to receive data.
class etsi_monitor : public monitor {
private:

    // Analysis engine
    cybermon::engine& an;

public:

    // Short-hand for vector iterator.
    typedef std::vector<unsigned char>::iterator iter;

    // Constructor.
    etsi_monitor(cybermon::engine& an) : an(an) {}

    // Called when a PDU is received.
    virtual void operator()(const std::string& liid, const iter& s, 
			    const iter& e);

    // Called when attacker is discovered.
    void target_up(const std::string& liid, const tcpip::address& addr);

    // Called when attacker is disconnected.
    void target_down(const std::string& liid);
    
};

// Called when attacker is discovered.
void etsi_monitor::target_up(const std::string& liid,
			 const tcpip::address& addr)
{
    an.target_up(liid, addr);
}

// Called when attacker is discovered.
void etsi_monitor::target_down(const std::string& liid)
{
    an.target_down(liid);
}

// Called when a PDU is received.
void etsi_monitor::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{

    try {

	// Process the PDU
	an.process(liid, s, e);

    } catch (std::exception& e) {

	// Processing failure event.
	std::cerr << "Packet failed: " << e.what() << std::endl;

    }

}

class pcap_input : public pcap_reader {
private:
    cybermon::engine& e;
    int count;

public:
    pcap_input(const std::string& f, cybermon::engine& e) : 
	pcap_reader(f), e(e) {
	count = 0;
    }

    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* f);

};


void pcap_input::handle(unsigned long len, unsigned long captured, 
			const unsigned char* f)
{

    int datalink = pcap_datalink(p);

    if (datalink == DLT_EN10MB) {

	// IPv4 ethernet only
	if (f[12] != 8) return;
	if (f[13] != 0) return;

	std::vector<unsigned char> v;
	v.assign(f + 14, f + len);

	// FIXME: Hard-coded?!
	std::string liid = "PCAP";

	try {
	    e.process(liid, v.begin(), v.end());
	} catch (std::exception& e) {
	    std::cerr << "Packet not processed: " << e.what() << std::endl;
	}
    }

}

int main(int argc, char** argv)
{

    namespace po = boost::program_options;

    std::string key, cert, chain;
    unsigned int port;
    std::string pcap_file, config_file;
    std::string transport;

    po::options_description desc("Supported options");
    desc.add_options()
	("help,h", "Show options guidance")
	("transport,t",
	 po::value<std::string>(&transport)->default_value("tcp"),
	 "Transport service to provide, one of: tls, tcp")
	("key,K", po::value<std::string>(&key), "server private key file")
	("certificate,C", po::value<std::string>(&cert),
	 "server public key file")
	("trusted-ca,T", po::value<std::string>(&chain), "server trusted CAs")
	("port,p", po::value<unsigned int>(&port), "port number to listen on")
	("pcap,f", po::value<std::string>(&pcap_file), "PCAP file to read")
	("config,c", po::value<std::string>(&config_file),
	 "LUA configuration file");

    po::variables_map vm;
    try {

	po::store(po::parse_command_line(argc, argv, desc), vm);

	po::notify(vm);

	if (config_file == "")
	    throw std::runtime_error("Configuration file must be specified.");

	if (pcap_file == "" && port == 0)
	    throw std::runtime_error("Must specify a PCAP file or a port.");

	if (pcap_file != "" && port != 0)
	    throw std::runtime_error("Specify EITHER a PCAP file OR a port.");
	    	    
	if (pcap_file == "") {

	    if (transport != "tls" && transport != "tcp")
		throw std::runtime_error("Transport most be one of: tcp, tls");

	    if (transport == "tls" && key == "")
		throw std::runtime_error("For TLS, key file must be provided.");

	    if (transport == "tls" && cert == "")
		throw std::runtime_error("For TLS, certificate file must be "
					 "provided.");

	    if (transport == "tls" && chain == "")
		throw std::runtime_error("For TLS, CA chain file must be "
					 "provided.");

	}

    } catch (std::exception& e) {
	std::cerr << "Exception: " << e.what() << std::endl;
	std::cerr << desc << std::endl;
	return 1;
    }

    if (vm.count("help")) {
	std::cerr << desc << std::endl;
	return 1;
    }

    try {
	
	// Create the observer instance.
	obs an(config_file);
	
	// Start the observer.
	an.start();

	std::string arg1(argv[1]);

	if (pcap_file != "") {

	    pcap_input pin(arg1.substr(5), an);
	    pin.run();

	} else if (transport == "tls") {

	    boost::shared_ptr<tcpip::ssl_socket> sock(new tcpip::ssl_socket);
	    sock->bind(port);
	    sock->use_key_file(key);
	    sock->use_certificate_file(cert);
	    sock->use_certificate_chain_file(chain);

	    // Create the monitor instance, receives ETSI events, and processes
	    // data.
	    etsi_monitor m(an);

	    // Start an ETSI receiver.
	    cybermon::etsi_li::receiver r(sock, m);
	    r.start();

	    // Wait forever.
	    r.join();	    

	} else {
	
	    // Create the monitor instance, receives ETSI events, and processes
	    // data.
	    etsi_monitor m(an);

	    // Start an ETSI receiver.
	    cybermon::etsi_li::receiver r(port, m);
	    r.start();

	    // Wait forever.
	    r.join();

	}
	    
    } catch (std::exception& e) {
	
	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;
	
    }

}


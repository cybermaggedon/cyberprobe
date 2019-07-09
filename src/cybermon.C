
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
#include <cybermon_qwriter.h>
#include <cybermon_qreader.h>
#include <cybermon/pdu.h>
#include <cybermon/event.h>
#include <cybermon/vxlan.h>

// Monitor class, implements the monitor interface to receive data.
class monitor : public cybermon::monitor {
private:

    // Analysis engine
    cybermon::engine& an;

public:

    // Short-hand for vector iterator.
    typedef std::vector<unsigned char>::const_iterator iter;

    // Constructor.
    monitor(cybermon::engine& an) : an(an) {}

    // Called when a PDU is received.
    virtual void operator()(const std::string& liid,
			    const std::string& network,
			    iter s, iter e,
			    const struct timeval& tv, cybermon::direction d);

    // Called when attacker is discovered.
    void target_up(const std::string& liid,
		   const std::string& network,
		   const tcpip::address& addr,
		   const struct timeval& tv);

    // Called when attacker is disconnected.
    void target_down(const std::string& liid,
		     const std::string& network,
		     const struct timeval& tv);

};

// Called when attacker is discovered.
void monitor::target_up(const std::string& liid,
			     const std::string& network,
			     const tcpip::address& addr,
			     const struct timeval& tv)
{
    an.target_up(liid, network, addr, tv);
}

// Called when attacker is discovered.
void monitor::target_down(const std::string& liid,
			       const std::string& network,
			       const struct timeval& tv)
{
    an.target_down(liid, network, tv);
}

// Called when a PDU is received.
void monitor::operator()(const std::string& liid,
                         const std::string& network,
                         iter s, iter e,
                         const struct timeval& tv, cybermon::direction d)
{

    try {

	// Process the PDU
        an.process(liid, network, cybermon::pdu_slice(s, e, tv, d));

    } catch (std::exception& e) {

	// Processing failure event.
	std::cerr << "Packet failed: " << e.what() << std::endl;

    }

}

class pcap_input : public pcap_reader {
private:
    cybermon::engine& e;
    int count;

    std::thread* thr;

public:
    pcap_input(const std::string& f, cybermon::engine& e) :
	pcap_reader(f), e(e) {
	count = 0;
    }

    virtual void stop() {
	pcap_reader::stop();
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&pcap_input::run, this);
    }

    virtual void handle(timeval tv, unsigned long len, const unsigned char* f);

};


void pcap_input::handle(timeval tv, unsigned long len, const unsigned char* f)
{

    int datalink = pcap_datalink(p);

    try {

	if (datalink == DLT_EN10MB) {

	    // If not long enough, return.
	    if (len < 14) return;

	    // IPv4 ethernet
	    if (f[12] == 0x08 && f[13] == 0) {

		std::vector<unsigned char> v;
		v.assign(f + 14, f + len);

		// FIXME: Hard-coded?!
		std::string liid = "PCAP";

		e.process(liid, "",
			  cybermon::pdu_slice(v.begin(), v.end(), tv));

	    }

	    // IPv6 ethernet only
	    if (f[12] == 0x86 && f[13] == 0xdd) {

		std::vector<unsigned char> v;
		v.assign(f + 14, f + len);

		// FIXME: Hard-coded?!
		std::string liid = "PCAP";

		e.process(liid, "",
			  cybermon::pdu_slice(v.begin(), v.end(), tv));

	    }

	    // 802.1q (VLAN)
	    if (f[12] == 0x81 && f[13] == 0x00) {

		// IPv4 ethernet
		if (f[16] == 0x08 && f[17] == 0) {

		    std::vector<unsigned char> v;
		    v.assign(f + 18, f + len);

		    // FIXME: Hard-coded?!
		    std::string liid = "PCAP";

		    e.process(liid, "",
			      cybermon::pdu_slice(v.begin(), v.end(), tv));

		}

		// IPv6 ethernet only
		if (f[16] == 0x86 && f[17] == 0xdd) {

		    std::vector<unsigned char> v;
		    v.assign(f + 18, f + len);

		    // FIXME: Hard-coded?!
		    std::string liid = "PCAP";

		    e.process(liid, "",
			      cybermon::pdu_slice(v.begin(), v.end(), tv));

		}

	    }

	}

	if (datalink == DLT_RAW) {

	    std::vector<unsigned char> v;
	    v.assign(f, f + len);

	    // FIXME: Hard-coded?!
	    std::string liid = "PCAP";

	    std::string str( v.begin(), v.end() );

	    e.process(liid, "",
		      cybermon::pdu_slice(v.begin(), v.end(), tv));

	}

    } catch (std::exception& e) {
	std::cerr << "Packet not processed: " << e.what() << std::endl;
    }

}

int main(int argc, char** argv)
{

    namespace po = boost::program_options;

    std::string key, cert, chain;
    unsigned int port = 0;
    unsigned int vxlan_port = 0;
    std::string pcap_file, config_file;
    std::string transport;
    float time_limit = -1;

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
	("vxlan,V", po::value<unsigned int>(&vxlan_port),
         "VXLAN port to listen on")
        ("time-limit,L", po::value<float>(&time_limit),
         "Describes a time limit (seconds) after which to stop.")
	("config,c", po::value<std::string>(&config_file),
	 "LUA configuration file");

    po::variables_map vm;
    try {

	po::store(po::parse_command_line(argc, argv, desc), vm);

	po::notify(vm);

	if (config_file == "")
	    throw std::runtime_error("Configuration file must be specified.");

	if (pcap_file == "" && port == 0 && vxlan_port == 0)
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

	//queue to store the incoming packets to be processed

        typedef std::shared_ptr<cybermon::event::event> eptr;
	std::queue<eptr> cqueue;

        // Input queue: Lock,
        std::mutex cqwrlock;

        //creating cybermon_qwriter and cybermon_qreader
        cybermon::cybermon_qwriter cqw(config_file, cqueue, cqwrlock);
        cybermon::cybermon_qreader cqr(config_file, cqueue, cqwrlock, cqw);

        //starting qreader and then qwriter
        cqr.start();
        cqw.start();

	if (pcap_file != "") {

            pcap_input pin(pcap_file, cqw);

            pin.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                pin.stop();
            }

            pin.join();

        } else if (vxlan_port != 0) {

            monitor m(cqw);

            cybermon::vxlan::receiver r(vxlan_port, m);

            r.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                r.stop();
            }

            r.join();

	} else if (transport == "tls") {

	    std::shared_ptr<tcpip::ssl_socket> sock(new tcpip::ssl_socket);
	    sock->bind(port);
	    sock->use_key_file(key);
	    sock->use_certificate_file(cert);
	    sock->use_certificate_chain_file(chain);
	    sock->check_private_key();

	    // Create the monitor instance, receives ETSI events, and processes
	    // data.
	    monitor m(cqw);

	    // Start an ETSI receiver.
	    cybermon::etsi_li::receiver r(sock, m);
	    r.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                r.stop();
            }

	    r.join();

	} else {

	    // Create the monitor instance, receives ETSI events, and processes
	    // data.
            monitor m(cqw);
	    // Start an ETSI receiver.
	    cybermon::etsi_li::receiver r(port, m);
	    r.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                r.stop();
            }

	    r.join();

	}

	// here
	//writer close to flag reader to stop
	//join reader
	cqw.close();
	cqr.join();

    } catch (std::exception& e) {

	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;

    }

}


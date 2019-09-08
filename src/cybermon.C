
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

#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/engine.h>
#include <cyberprobe/analyser/monitor.h>
#include <cyberprobe/analyser/lua.h>
#include <cyberprobe/pkt_capture/packet_capture.h>
#include <cyberprobe/stream/vxlan.h>
#include <cyberprobe/stream/etsi_li.h>
#include <cyberprobe/event/event_queue.h>
#include <cyberprobe/event/event.h>

using namespace cyberprobe;
using namespace cyberprobe::protocol;
using namespace cyberprobe::analyser;

class lua_engine : event::observer {
private:
    std::thread* thr;

public:
    engine& m;
    event::queue& q;
    lua cml;
    
    lua_engine(engine& m,
               event::queue& q,
               const std::string& config) :
        m(m), q(q), cml(config) {}

    virtual ~lua_engine() {}

    virtual void run() {
        q.run(*this);
    }

    virtual void handle(std::shared_ptr<event::event> e) {
        cml.event(m, e);
    }

    virtual void stop() {
        // Put null pointer on queue to indicate end of stream.
        q.stop();
    }
    
    virtual void join() {
        if (thr) thr->join();
    }
    
    virtual void start() {
        thr = new std::thread(&lua_engine::run, this);
    }
    
};

class protocol_engine : public engine {
private:

    // Analysis engine
    event::queue& q;

public:

    // Constructor.
    protocol_engine(event::queue& q) : q(q) {}

    virtual void handle(std::shared_ptr<event::event> e) {
        q.push(e);
    }

    typedef std::vector<unsigned char>::const_iterator iter;

    using engine::target_up;
    using engine::target_down;
    
    // Called when a PDU is received.
    virtual void operator()(const std::string& device,
			    const std::string& network,
                            pdu_slice p) {
        try {
            // Process the PDU
            engine::process(device, network, p);
        } catch (std::exception& e) {
            // Processing failure event.
            std::cerr << "Packet failed: " << e.what() << std::endl;
        }
    }

};

class pcap_input : public pcap::packet_handler {
private:
    engine& e;
    std::string device;


public:
    pcap_input(engine& e, const std::string& device) :
	e(e), device(device)
        {
        }

    virtual void handle(timeval tv, unsigned long len, const unsigned char* f);

    virtual int get_datalink() = 0;

};

class interface_input : public pcap_input, public pcap::interface {

private:
    std::thread* thr;

public:
    interface_input(const std::string& iface, engine& e,
               const std::string& device) :
        pcap_input(e, device), interface(*this, iface)
        {
        }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&interface::run, this);
    }

    virtual void stop() {
	interface::stop();
    }

    virtual int get_datalink() { return pcap_datalink(p); }

};

class file_input : public pcap_input, public pcap::reader {

private:
    std::thread* thr;

public:
    file_input(const std::string& file, engine& e,
               const std::string& device) :
        pcap_input(e, device), reader(*this, file)
        {
        }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
    virtual void start() {
	thr = new std::thread(&reader::run, this);
    }

    virtual void stop() {
	reader::stop();
    }

    virtual int get_datalink() { return pcap_datalink(p); }

};

void pcap_input::handle(timeval tv, unsigned long len, const unsigned char* f)
{

    int datalink = get_datalink();

    try {

	if (datalink == DLT_EN10MB) {

	    // If not long enough, return.
	    if (len < 14) return;

	    // IPv4 ethernet
	    if (f[12] == 0x08 && f[13] == 0) {

		std::vector<unsigned char> v;
		v.assign(f + 14, f + len);

		e.process(device, "",
			  pdu_slice(v.begin(), v.end(), tv));

	    }

	    // IPv6 ethernet only
	    if (f[12] == 0x86 && f[13] == 0xdd) {

		std::vector<unsigned char> v;
		v.assign(f + 14, f + len);

		e.process(device, "",
			  pdu_slice(v.begin(), v.end(), tv));

	    }

	    // 802.1q (VLAN)
	    if (f[12] == 0x81 && f[13] == 0x00) {

		// IPv4 ethernet
		if (f[16] == 0x08 && f[17] == 0) {

		    std::vector<unsigned char> v;
		    v.assign(f + 18, f + len);

		    e.process(device, "",
			      pdu_slice(v.begin(), v.end(), tv));

		}

		// IPv6 ethernet only
		if (f[16] == 0x86 && f[17] == 0xdd) {

		    std::vector<unsigned char> v;
		    v.assign(f + 18, f + len);

		    e.process(device, "",
			      pdu_slice(v.begin(), v.end(), tv));

		}

	    }

	}

	if (datalink == DLT_RAW) {

	    std::vector<unsigned char> v;
	    v.assign(f, f + len);

	    std::string str( v.begin(), v.end() );

	    e.process(device, "",
		      pdu_slice(v.begin(), v.end(), tv));

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
    std::string pcap_input, config_file;
    std::string transport;
    std::string device;
    std::string interface;
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
	("pcap,f", po::value<std::string>(&pcap_input), "PCAP file to read")
	("interface,i", po::value<std::string>(&interface),
         "Interface to monitor")
	("vxlan,V", po::value<unsigned int>(&vxlan_port),
         "VXLAN port to listen on")
        ("time-limit,L", po::value<float>(&time_limit),
         "Describes a time limit (seconds) after which to stop.")
	("config,c", po::value<std::string>(&config_file),
	 "LUA configuration file")
        ("device,d", po::value<std::string>(&device),
         "Device ID to use for PCAP file");

    po::variables_map vm;
    try {

	po::store(po::parse_command_line(argc, argv, desc), vm);

	po::notify(vm);

	if (config_file == "")
	    throw std::runtime_error("Configuration file must be specified.");

	if (pcap_input == "" && port == 0 && vxlan_port == 0 && interface == "")
	    throw std::runtime_error("Must specify PCAP file, interface, port or VXLAN input.");

	if (pcap_input != "" && port != 0)
	    throw std::runtime_error("Can't specify both PCAP file and port.");

	if (port != 0) {

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

	// queue to store the incoming packets to be processed
        event::queue queue;

        protocol_engine pe(queue);
        lua_engine le(pe, queue, config_file);

	if (interface != "") {

            if (device == "") device = "PCAP";

            interface_input pin(interface, pe, device);

            le.start();
            pin.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                pin.stop();
            }

            pin.join();

        } else if (pcap_input != "") {

            if (device == "") device = "PCAP";
            file_input pin(pcap_input, pe, device);

            le.start();
            pin.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                pin.stop();
            }

            pin.join();

        } else if (vxlan_port != 0) {

            vxlan::receiver r(vxlan_port, pe);

            // Over-ride VNI??? device for VXLAN if device was specified
            // on command line.
            if (device != "")
                r.device = device;

            le.start();
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

	    // Start an ETSI receiver.
	    etsi_li::receiver r(sock, pe);

            le.start();
	    r.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                r.stop();
            }

	    r.join();

	} else {

	    // Start an ETSI receiver.
	    etsi_li::receiver r(port, pe);

            le.start();
	    r.start();

            if (time_limit > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                                                long(time_limit * 1000)));
                r.stop();
            }

	    r.join();

	}

        le.stop();
        le.join();

    } catch (std::exception& e) {

	std::cerr << "Exception: " << e.what() << std::endl;
	return 1;

    }

}


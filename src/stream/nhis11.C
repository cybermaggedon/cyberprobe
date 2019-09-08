
#include <sys/time.h>

#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/stream/transport.h>
#include <cyberprobe/stream/nhis11.h>

#include <string>
#include <vector>

using namespace cyberprobe::nhis11;
using namespace cyberprobe::protocol;

// Next CID counter.
unsigned long sender::next_cid;

// Send a START PDU.
void sender::send_start(const std::string& liid)
{

    pdu_ptr buffer = pdu_ptr(new pdu);

    // Magic.
    buffer->push_back('c');
    buffer->push_back('}');

    // Version number is zero.
    buffer->push_back(0);
    buffer->push_back(0);

    // LIID.
    for(std::string::const_iterator it = liid.begin();
	it != liid.end(); it++)
	buffer->push_back(*it);

    // Zero pad to 28 bytes, (32 minus the 4 byte header)
    for(int i = 28 - liid.length(); i >- 0; i--)
	buffer->push_back(0);

    // Send the start PDU.
    int ret = s.write(buffer);
    if (ret <= 0)
	throw std::runtime_error("NHIS 1.1 START write fail.");

}

// Send an IP packet.
void sender::send_ip(const std::vector<unsigned char>& pkt, 
		     unsigned long seq, unsigned long long cid,
		     bool direction)
{

    pdu_ptr buffer = pdu_ptr(new pdu);
    buffer->clear();

    // Version & direction
    buffer->push_back(0x1c + (direction ? 2 : 0));
    
    // Message type, not used.
    buffer->push_back(0xff);

    // Length
    buffer->push_back((pkt.size() >> 8) & 0xff);
    buffer->push_back(pkt.size() & 0xff);

    // Sequence
    buffer->push_back((seq >> 8) & 0xff);
    buffer->push_back(seq & 0xff);
    
    // Not used
    buffer->push_back(0);
    buffer->push_back(0);
    buffer->push_back(0xff);
    buffer->push_back(0xff);
    buffer->push_back(0xff);
    buffer->push_back(0xff);

    // CID
    buffer->push_back((cid >> 56) & 0xff);
    buffer->push_back((cid >> 48) & 0xff);
    buffer->push_back((cid >> 40) & 0xff);
    buffer->push_back((cid >> 32) & 0xff);
    buffer->push_back((cid >> 24) & 0xff);
    buffer->push_back((cid >> 16) & 0xff);
    buffer->push_back((cid >> 8) & 0xff);
    buffer->push_back(cid & 0xff);

    for(unsigned int i = 0; i < pkt.size(); i++)
	buffer->push_back(pkt[i]);

    // Send the IP packet.
    int ret = s.write(buffer);
    if (ret <= 0)
	throw std::runtime_error("NHIS 1.1 CONTINUE write fail.");

}

void receiver::run()
{

    try {

	svr->listen();

	while (running) {
	    
	    bool activ = svr->poll(1.0);
	    
	    if (activ) {
		
		std::shared_ptr<tcpip::stream_socket> cn = svr->accept();
		
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

void connection::run()
{

    try {

	std::vector<unsigned char> pdu;

	// Read NHIS 1.1 START.
	s->read(pdu, 32);
	
	if (pdu[0] != 'c' || pdu[1] != '}')
	    throw std::runtime_error("START PDU is not valid.");

	// Get LIID.
	std::string liid;
	for (int i = 4; i < 32; i++)
	    if (pdu[i] != 0) liid += pdu[i];

	while (running) {
	
	    // NHIS 1.1 continue header.
	    pdu.clear();
	    unsigned int ret = s->read(pdu, 20);
	    if (ret <= 0) break;

	    if ((pdu[0] & 0xfc) != 0x1c)
		throw std::runtime_error("Not an NHIS 1.1 continue PDU.");

	    if (pdu[1] != 0xff)
		throw std::runtime_error("Not an NHIS 1.1 continue PDU.");

	    unsigned int length = (pdu[2] << 8) + pdu[3];

	    // Get the IP packet.
	    pdu.clear();
	    ret = s->read(pdu, length);
	    if (ret <= 0) break;

	    if (ret != length) break;

	    struct timeval tv;
	    gettimeofday(&tv, 0);
	    p(liid, "",
              pdu_slice(pdu.begin(), pdu.end(), tv, direction::NOT_KNOWN));

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


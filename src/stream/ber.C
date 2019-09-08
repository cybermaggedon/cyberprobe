
#include <cyberprobe/stream/ber.h>

#include <algorithm>
#include <iterator>

using namespace cyberprobe::stream::ber;

bool berpdu::read_pdu(tcpip::stream_socket& sock)
{

    data->clear();
    is_decoded = false;
    contained_pdus.clear();
    
    unsigned char c;

    int len = sock.read((char*) &c, 1);
    if (len != 1) return false;

    data->push_back(c);
    
    // Deal with long tag form.
    if ((c & 0x1f) == 0x1f)
	while (1) {
	    int len = sock.read((char*) &c, 1);
	    if (len != 1) return false;
	    data->push_back(c);
	    if (c & 0x80) break;
	}

    // Now on to the length.
    long length = 0;
    len = sock.read((char*) &c, 1);
    if (len != 1) return false;

    data->push_back(c);
    if ((c & 0x80) == 0) {
	length = c;
    } else {
	// Length of the length.
	int blen = c & 0x7f;
	for(int i = 0; i < blen; i++) {
	    int len = sock.read((char*) &c, 1);
	    if (len != 1) return false;
	    data->push_back(c);
	    length <<= 8;
	    length |= c;
	}
    }

    // Bail out for PDUs bigger than 1GB.
    if (length > (1024 * 1024 * 1024)) {
	return false;
    }

    unsigned char payload[length];

    len = sock.read((char *)payload, length);
    if (len != length) return false;

    data->insert(data->end(), payload, payload+length);

    return true;

}

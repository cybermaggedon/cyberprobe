
#ifndef CYBERMON_PDU_H
#define CYBERMON_PDU_H

#include <vector>

namespace cybermon {

    typedef std::vector<unsigned char> pdu;
    typedef std::vector<unsigned char>::const_iterator pdu_iter;

    typedef struct timeval pdu_time;
    
    class pdu_slice {
      public:
	pdu_slice(pdu_iter start, pdu_iter end, const struct timeval& tv) {
	    this->start = start;
	    this->end = end;
	    this->time = tv;
	}
	pdu_iter start, end;
	struct timeval time;
    };


};

#endif


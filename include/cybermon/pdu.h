
#ifndef CYBERMON_PDU_H
#define CYBERMON_PDU_H

#include <vector>
#include <sys/time.h>

namespace cybermon {

    typedef std::vector<unsigned char> pdu;
    typedef std::vector<unsigned char>::const_iterator pdu_iter;

    typedef struct timeval pdu_time;

    typedef enum { FROM_TARGET, TO_TARGET, NOT_KNOWN } direction;
    
    class pdu_slice {
    public:
	pdu_slice(pdu_iter start, pdu_iter end, const struct timeval& tv,
                  direction d = NOT_KNOWN) {
	    this->start = start;
	    this->end = end;
	    this->time = tv;
            this->direc = d;
            
	}
	pdu_iter start, end;
	struct timeval time;
        direction direc;

        pdu_slice skip(int n) const {
            return pdu_slice(start + n, end, time, direc);
        }

    };

};

#endif


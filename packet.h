
#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <vector>

// Virtual packet handling interface
class packet_processor {
  public:
    virtual void operator()(const std::string& liid,
			    const std::vector<unsigned char>::iterator&,
			    const std::vector<unsigned char>::iterator&) = 0;
};

#endif


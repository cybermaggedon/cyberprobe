
////////////////////////////////////////////////////////////////////////////
//
// Hex dump support
//
////////////////////////////////////////////////////////////////////////////

#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <iostream>
#include <iomanip>

class hexdump {

public:

    // Dump a bunch of data in a standard 'hexdump' fashion.
    // indent = number of spaces before hexdump, if you want to indent.
    // Data is described at iterator bounds s and e.
    // out is the output stream to hex dump to.
    static void dump(std::vector<unsigned char>::const_iterator s,
		     std::vector<unsigned char>::const_iterator e,
		     std::ostream& out, int indent = 0) {

	std::vector<unsigned char>::const_iterator it;
	std::string chrs;

	for(it = s; it != e; it++) {

	    if (((it - s) % 16) == 0) {

		for(int i = 0; i < indent; i++)
		    std::cout << " ";
		std::cout << std::hex << std::setfill('0') << std::setw(6) 
			  << (it - s) << ": ";
		chrs = "";
	    }

	    std::cout << std::hex << std::setfill('0') << std::setw(2)
		      << (int) *it;
	    std::cout << " ";

	    if (*it >= 32 && *it <= 126)
		chrs += *it;
	    else
		chrs += '.';
	    
	    if (((it - s) % 16) == 15) {
		std::cout << "| " << chrs << std::endl;
	    }
	}
	
	if (((it - s) % 16) != 0) {
	    for(int i = 0; i < (16 - ((it - s) % 16)); i++)
		std::cout << "   ";
		std::cout << "| " << chrs << std::endl;
	}
	
    }

};

#endif


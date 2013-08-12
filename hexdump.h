
#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <iostream>
#include <iomanip>

class hexdump {

public:

    static void dump(const std::vector<unsigned char>::iterator& s,
		     const std::vector<unsigned char>::iterator& e,
		     std::ostream& out) {

	std::vector<unsigned char>::const_iterator it;
	std::string chrs;

	for(it = s; it != e; it++) {

	    if (((it - s) % 16) == 0) {
		std::cout << "  ";
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



////////////////////////////////////////////////////////////////////////////
//
// Hex dump support
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_HEXDUMP_H
#define CYBERMON_HEXDUMP_H

#include <iostream>
#include <iomanip>

namespace cybermon {

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
                        out << " ";
                    out << std::hex << std::setfill('0') << std::setw(6) 
                        << (it - s) << ": ";
                    chrs = "";
                }

                out << std::hex << std::setfill('0') << std::setw(2)
                    << (int) *it;
                out << " ";

                if (*it >= 32 && *it <= 126)
                    chrs += *it;
                else
                    chrs += '.';
	    
                if (((it - s) % 16) == 15) {
                    out << "| " << chrs << std::endl;
                }
            }
	
            if (((it - s) % 16) != 0) {
                for(int i = 0; i < (16 - ((it - s) % 16)); i++)
                    out << "   ";
		out << "| " << chrs << std::endl;
            }
	
        }

    };

};

#endif


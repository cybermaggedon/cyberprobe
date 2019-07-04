
#include <cybermon/vxlan.h>
#include <cybermon/socket.h>

#include <vector>

using namespace cybermon::vxlan;

// VXLAN receiver
void receiver::run()
{

    std::cerr << "VXLAN mon running..." << std::endl;

    try {

	while (running) {

	    bool activ = svr->poll(1.0);

	    if (activ) {

                std::vector<unsigned char> buffer;

                svr->read(buffer, 65536);

                // Ignore truncated VXLAN.
                if (buffer.size() < 8) continue;

                timeval tv;
                gettimeofday(&tv, 0);

                p("VXLAN", "", buffer.begin() + 8, buffer.end(), tv,
                  NOT_KNOWN);
            
            }

        }


    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

}


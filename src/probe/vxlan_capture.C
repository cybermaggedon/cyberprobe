
#include <cyberprobe/probe/vxlan_capture.h>
#include <cyberprobe/network/socket.h>

#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace cyberprobe::capture;

// Capture device, main thread body.
void vxlan::run()
{

    try {

        // Start UDP service
        tcpip::udp_socket recv;
        recv.bind(port);

        while (running) {

            // Rattling around this loop allows clearing the delay line.
            bool activ = recv.poll(0.05);

            if (activ) {

                std::vector<unsigned char> buffer;
                
                recv.read(buffer, 65536);

                // Ignore truncated VXLAN.
                if (buffer.size() < 8) continue;

                // VXLAN header (8-bytes):
                //   Flags: 8-bits, bit 3 = VNI is valid.
                //   Reserved: 24 bits
                //   VNI: 24 bits
                //   Reserved: 8 bits

                // Start from the end of VXLAN header.
                std::vector<unsigned char>::const_iterator s =
                    buffer.begin() + 8;
                std::vector<unsigned char>::const_iterator e =
                    buffer.end();

                // filter check
                if (apply_filter(s, e)) {
                    
                    // Filter hits.
                    timeval tv = {0};
                    handle(tv, e - s, &s[0]);

                }
                
            }

            // Maybe clear some delay line.
            service_delayline();

        }

    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

}



#include <cyberprobe/stream/vxlan.h>
#include <cyberprobe/network/socket.h>
#include <cyberprobe/protocol/pdu.h>

#include <vector>

using namespace cyberprobe::vxlan;

// VXLAN receiver
void receiver::run()
{

    try {

	while (running) {

	    bool activ = svr->poll(0.5);

	    if (activ) {

                std::vector<unsigned char> buffer;

                svr->read(buffer, 65536);

                // Ignore truncated VXLAN.
                if (buffer.size() < 8) continue;

                // VXLAN header (8-bytes):
                //   Flags: 8-bits, bit 3 = VNI is valid.
                //   Reserved: 24 bits
                //   VNI: 24 bits
                //   Reserved: 8 bits

                uint32_t vxlan_id = 0;

                if (buffer[0] & (1 << 3))
                    vxlan_id = buffer[6] |
                        buffer[5] << 16 |
                        buffer[4] << 8;

                std::vector<unsigned char>::const_iterator p = buffer.begin();
                std::vector<unsigned char>::const_iterator end = buffer.end();

                // Skip VXLAN header
                p += 8;

                // Next is ethernet.  If not enough for an eth header,
                // assume truncated and move on.
                if ((end - p) < 14) continue;

                // Skip Ethernet

                // IPv4 case...
                if (p[12] == 0x08 && p[13] == 0) {
                    p += 14;	// Skip the Ethernet frame.

                } 

                // IPv6 case...
                else if (p[12] == 0x86 && p[13] == 0xdd) {
                    p += 14;	// Skip the Ethernet frame.
                }

                        
                // 802.1q (VLAN)
                else if (p[12] == 0x81 && p[13] == 0x00) {

                    // Ignore if truncated
                    if ((end - p) < 18) continue;

                    // IPv4 in VLAN
                    if (p[16] == 0x08 && p[17] == 0) {
                        p += 18;		// Skip the Ethernet frame.
                        // IPv6 in VLAN
                    }

                    else if (p[16] == 0x86 && p[17] == 0xdd) {
                        p += 18;		// Skip the Ethernet frame.
                    } else

                        // Not 4 or 6.
                        continue;

                } else continue;

                timeval tv;
                gettimeofday(&tv, 0);

                using pdu_slice = cyberprobe::protocol::pdu_slice;
                using direction = cyberprobe::protocol::direction;

                if (device == "") {
                    std::string vni_device;
                    vni_device = "VNI" + std::to_string(vxlan_id);
                    mon(vni_device, "",
                        pdu_slice(p, buffer.end(), tv, direction::NOT_KNOWN));
                } else
                    mon(device, "",
                        pdu_slice(p, buffer.end(), tv, direction::NOT_KNOWN));
            
            }

        }

    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

}


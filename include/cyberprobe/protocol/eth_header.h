
#ifndef ETH_HEADER_H
#define ETH_HEADER_H

namespace cybermon {

    namespace eth {

        enum next_proto {
            ETH_PROTO_NONE,
            ETH_PROTO_IPv4 = 4,
            ETH_PROTO_IPv6 = 6
        };

        using iter = std::vector<unsigned char>::const_iterator;

        // Returns true if header detected.
        // Start pointer reference is moved to start of next
        static next_proto skip_header(iter& s, iter e,
                                      unsigned int& vlan_id) {

            vlan_id = 0;

            // Ethernet header.  If not enough for an eth header,
            // assume truncated and move on.
            if ((e - s) < 14) return ETH_PROTO_NONE;

            // Skip Ethernet

            std::cerr << "eth " << (int) s[12] << ":" << (int) s[13]
                      << std::endl;

            // IPv4 case...
            if (s[12] == 0x08 && s[13] == 0) {
                s += 14;        // Skip the Ethernet frame.
                return ETH_PROTO_IPv4;
            } 

            // IPv6 case...
            if (s[12] == 0x86 && s[13] == 0xdd) {
                s += 14;	// Skip the Ethernet frame.
                return ETH_PROTO_IPv6;
            }

                        
            // 802.1q (VLAN)
            if (s[12] == 0x81 && s[13] == 0x00) {

                vlan_id = s[14] & 0xf + s[15];

                // Ignore if truncated
                if ((e - s) < 18)
                    return ETH_PROTO_NONE;

                // IPv4 in VLAN
                if (s[16] == 0x08 && s[17] == 0) {
                    s += 18;		// Skip the Ethernet frame.
                    return ETH_PROTO_IPv4;
                }

                if (s[16] == 0x86 && s[17] == 0xdd) {
                    s += 18;		// Skip the Ethernet frame.
                    return ETH_PROTO_IPv6;
                }
                
            }

            return ETH_PROTO_NONE;

        };

    };

};

#endif


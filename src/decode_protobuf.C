
#include <base64.h>
#include <string>
#include "cyberprobe.pb.h"

#include <google/protobuf/util/time_util.h>

int main(int argc, char** argv)

{

    try {

        std::string arg = argv[1];

        std::string dec = base64_decode(arg);

        std::cerr << "Decode length " << dec.size() << std::endl;

        cyberprobe::Event ev;

        if (!ev.ParseFromString(dec))
            throw std::runtime_error("Did not parse.");

        std::cout << "ID: " << ev.id() << std::endl;
        std::cout << "Action: " << ev.action() << std::endl;
        std::cout << "Device: " << ev.device() << std::endl;
        std::string tm =
            google::protobuf::util::TimeUtil::ToString(ev.time());
        std::cout << "Time: " << tm << std::endl;
        if (ev.network() != "")
            std::cout << "Network: " << ev.network() << std::endl;

        if (ev.has_unrecognised_stream()) {
            std::cout << "Unrecognised stream: "<< std::endl;
            std::cout << "  Payload length: "
                      << ev.unrecognised_stream().payload().size() << std::endl;
            std::cout << "  position: "
                      << ev.unrecognised_stream().position() << std::endl;
        }
        
        if (ev.has_unrecognised_datagram()) {
            std::cout << "Unrecognised datagram payload length: "
                      << ev.unrecognised_datagram().payload().size()
                      << std::endl;
        }

        if (ev.has_icmp()) {
            std::cout << "ICMP:" << std::endl
                      << "  Type: " << ev.icmp().type() << std::endl
                      << "  Code: " << ev.icmp().code() << std::endl
                      << "  Payload length: " << ev.icmp().payload().size()
                      << std::endl;
        }
                
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

}


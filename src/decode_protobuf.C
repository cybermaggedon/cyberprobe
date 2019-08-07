
#include <iostream>
#include <iomanip>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include <google/protobuf/util/time_util.h>

#include "cyberprobe.grpc.pb.h"
#include <cybermon/socket.h>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using cyberprobe::Event;
using cyberprobe::Empty;
using cyberprobe::EventStream;
using google::protobuf::util::TimeUtil;

// Logic and data behind the server's behavior.
class EventStreamServiceImpl final : public EventStream::Service {
    Status Observe(ServerContext* context, const Event* request,
                    Empty* reply) override {

        std::cout << std::endl;
        std::cout << std::setw(30) << std::left
                  << "Id: " << request->id() << std::endl;
       std::cout << std::setw(30) << std::left
                 << "Time: " << TimeUtil::ToString(request->time()) << std::endl;
       std::cout << std::setw(30) << std::left
                  << "Action: " << Action_Name(request->action())
                  << std::endl;
        std::cout << std::setw(30) << std::left
                  << "Device: " << request->device()
                  << std::endl;
        if (request->network() != "")
            std::cout << std::setw(30) << std::left
                      << "Network: " << request->network()
                      << std::endl;
        if (request->origin() == cyberprobe::Origin::network)
            std::cout << std::setw(30) << std::left
                      << "Origin: " << "network"
                      << std::endl;
        else if (request->origin() == cyberprobe::Origin::device)
            std::cout << std::setw(30) << std::left
                      << "Origin: " << "device"
                      << std::endl;

        std::cout << std::setw(30) << std::left << "Src: ";
        for(auto it = request->src().begin();
            it != request->src().end();
            it++) {
            std::cout << cyberprobe::Protocol_Name(it->protocol());

            auto a = it->address();

            if (a.address_variant_case() == cyberprobe::Address::kIpv4) {
                std::cout << ":"
                          << ((it->address().ipv4() >> 24) & 0xff) << "."
                          << ((it->address().ipv4() >> 16) & 0xff) << "."
                          << ((it->address().ipv4() >> 8) & 0xff) << "."
                          << (it->address().ipv4() & 0xff);
            }

            if (a.address_variant_case() == cyberprobe::Address::kIpv6) {
                tcpip::ip6_address ip;
                ip.addr.assign(it->address().ipv6().begin(),
                               it->address().ipv6().end());
                std::string a;
                ip.to_string(a);
                std::cout << ":" << a;
            }

            if (a.address_variant_case() == cyberprobe::Address::kPort) {
                std::cout << ":" << it->address().port();
            }

            std::cout << " ";
        }
        std::cout << std::endl;

        std::cout << std::setw(30) << std::left << "Dest: ";
        for(auto it = request->dest().begin();
            it != request->dest().end();
            it++) {
            std::cout << cyberprobe::Protocol_Name(it->protocol());

            auto a = it->address();

            if (a.address_variant_case() == cyberprobe::Address::kIpv4) {
                std::cout << ":"
                          << ((it->address().ipv4() >> 24) & 0xff) << "."
                          << ((it->address().ipv4() >> 16) & 0xff) << "."
                          << ((it->address().ipv4() >> 8) & 0xff) << "."
                          << (it->address().ipv4() & 0xff);
            }

            if (a.address_variant_case() == cyberprobe::Address::kIpv6) {
                tcpip::ip6_address ip;
                ip.addr.assign(it->address().ipv6().begin(),
                               it->address().ipv6().end());
                std::string a;
                ip.to_string(a);
                std::cout << ":" << a;
            }

            if (a.address_variant_case() == cyberprobe::Address::kPort) {
                std::cout << ":" << it->address().port();
            }

            std::cout << " ";
        }
        std::cout << std::endl;

        return Status::OK;
    }
};

void run() {

    std::string server_address("0.0.0.0:50051");
    EventStreamServiceImpl service;

    ServerBuilder builder;

    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&service);

    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();

}

int main(int argc, char** argv) {

    run();
    return 0;

}


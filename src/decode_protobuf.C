
#include <iostream>
#include <iomanip>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include <google/protobuf/util/time_util.h>

#include "cyberprobe.grpc.pb.h"

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


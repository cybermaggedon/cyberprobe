
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>

#ifdef WITH_PROTOBUF
#include <google/protobuf/util/time_util.h>

#ifdef WITH_GRPC
#include <grpcpp/grpcpp.h>
#include "cyberprobe.grpc.pb.h"
#endif

#endif

#include <cybermon/socket.h>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using cyberprobe::Event;
using cyberprobe::Empty;
using cyberprobe::EventStream;
using google::protobuf::util::TimeUtil;
using grpc::ServerCompletionQueue;
using grpc::ServerAsyncResponseWriter;

const int indent = 15;

void display(const cyberprobe::Event& ev) {

                
    std::cout << std::endl;
    std::cout << std::setw(indent) << std::left
              << "Id: " << ev.id() << std::endl;
    std::cout << std::setw(indent) << std::left
              << "Time: " << TimeUtil::ToString(ev.time()) << std::endl;
    std::cout << std::setw(indent) << std::left
              << "Action: " << Action_Name(ev.action())
              << std::endl;
    std::cout << std::setw(indent) << std::left
              << "Device: " << ev.device()
              << std::endl;
    if (ev.network() != "")
        std::cout << std::setw(indent) << std::left
                  << "Network: " << ev.network()
                  << std::endl;
    if (ev.origin() == cyberprobe::Origin::network)
        std::cout << std::setw(indent) << std::left
                  << "Origin: " << "network"
                  << std::endl;
    else if (ev.origin() == cyberprobe::Origin::device)
        std::cout << std::setw(indent) << std::left
                  << "Origin: " << "device"
                  << std::endl;

    std::cout << std::setw(indent) << std::left << "Src: ";
    for(auto it = ev.src().begin();
        it != ev.src().end();
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

    std::cout << std::setw(indent) << std::left << "Dest: ";
    for(auto it = ev.dest().begin();
        it != ev.dest().end();
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

}

class ServerImpl final {
public:
    ~ServerImpl() {

        server->Shutdown();

        // Always shutdown the completion queue after the server.
        cq->Shutdown();

    }

    // There is no shutdown handling in this code.
    void Run() {

        std::string serveraddress("0.0.0.0:50051");

        ServerBuilder builder;

        // Listen on the given address without any authentication mechanism.
        builder.AddListeningPort(serveraddress,
                                 grpc::InsecureServerCredentials());

        // Register "service" as the instance through which we'll
        // communicate with clients. In this case it corresponds to an
        // *asynchronous* service.
        builder.RegisterService(&service);

        // Get hold of the completion queue used for the asynchronous
        // communication with the gRPC runtime.
        cq = builder.AddCompletionQueue();

        // Finally assemble the server.
        server = builder.BuildAndStart();
        std::cout << "Server listening on " << serveraddress << std::endl;

        // Proceed to the server's main loop.
        handle_rpcs();
    }

private:

    // Class encompasing the state and logic needed to serve a request.
    class CallData {
    public:

        // Take in the "service" instance (in this case representing an
        // asynchronous server) and the completion queue "cq" used for
        // asynchronous communication with the gRPC runtime.
        CallData(cyberprobe::EventStream::AsyncService* service,
                 ServerCompletionQueue* cq)
            : service(service), cq(cq), responder(&ctx), status(CREATE) {
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed() {

            if (status == CREATE) {

                // Make this instance progress to the PROCESS state.
                status = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing SayHello requests. In this request, "this" acts are
                // the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.
                service->RequestObserve(&ctx, &request, &responder, cq,
                                        cq, this);

            } else if (status == PROCESS) {

                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallData(service, cq);

                display(request);

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status = FINISH;
                responder.Finish(reply, Status::OK, this);
            } else {
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }
        }

    private:
        // The means of communication with the gRPC runtime for an asynchronous
        // server.
        cyberprobe::EventStream::AsyncService* service;
        // The producer-consumer queue where for asynchronous server notifications.
        ServerCompletionQueue* cq;
        // Context for the rpc, allowing to tweak aspects of it such as the use
        // of compression, authentication, as well as to send metadata back to the
        // client.
        ServerContext ctx;

        // What we get from the client.
        Event request;
        // What we send back to the client.
        Empty reply;

        // The means to get back to the client.
        ServerAsyncResponseWriter<Empty> responder;

        // Let's implement a tiny state machine with the following states.
        enum CallStatus { CREATE, PROCESS, FINISH };
        CallStatus status;  // The current serving state.
    };

    // This can be run in multiple threads if needed.
    void handle_rpcs() {
        // Spawn a new CallData instance to serve new clients.
        new CallData(&service, cq.get());
        void* tag;  // uniquely identifies a request.
        bool ok;
        while (true) {
            // Block waiting to read the next event from the completion queue. The
            // event is uniquely identified by its tag, which in this case is the
            // memory address of a CallData instance.
            // The return value of Next should always be checked. This return value
            // tells us whether there is any kind of event or cq is shutting down.
            GPR_ASSERT(cq->Next(&tag, &ok));
            static_cast<CallData*>(tag)->Proceed();
        }
    }

    std::unique_ptr<ServerCompletionQueue> cq;
    cyberprobe::EventStream::AsyncService service;
    std::unique_ptr<Server> server;
};

int main(int argc, char** argv) {
    ServerImpl server;
    server.Run();

    return 0;
}


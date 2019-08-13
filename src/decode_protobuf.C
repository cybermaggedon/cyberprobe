
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
using grpc::ServerCompletionQueue;
using grpc::ServerAsyncResponseWriter;

class ServerImpl final {
public:
    ~ServerImpl() {

        server_->Shutdown();

        // Always shutdown the completion queue after the server.
        cq_->Shutdown();

    }

    // There is no shutdown handling in this code.
    void Run() {

        std::string server_address("0.0.0.0:50051");

        ServerBuilder builder;

        // Listen on the given address without any authentication mechanism.
        builder.AddListeningPort(server_address,
                                 grpc::InsecureServerCredentials());

        // Register "service_" as the instance through which we'll
        // communicate with clients. In this case it corresponds to an
        // *asynchronous* service.
        builder.RegisterService(&service_);

        // Get hold of the completion queue used for the asynchronous
        // communication with the gRPC runtime.
        cq_ = builder.AddCompletionQueue();

        // Finally assemble the server.
        server_ = builder.BuildAndStart();
        std::cout << "Server listening on " << server_address << std::endl;

        // Proceed to the server's main loop.
        HandleRpcs();
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
            : service_(service), cq_(cq), responder_(&ctx_), status_(CREATE) {
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed() {

            if (status_ == CREATE) {

                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing SayHello requests. In this request, "this" acts are
                // the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.
                service_->RequestObserve(&ctx_, &request_, &responder_, cq_,
                                         cq_, this);

            } else if (status_ == PROCESS) {

                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallData(service_, cq_);


std::cout << std::setw(30) << std::left
<< "Id: " << request_.id() << std::endl;

                // The actual processing.
                // DO nothing.
//                std::string prefix("Hello ");
//                reply_.set_message(prefix + request_.name());

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                responder_.Finish(reply_, Status::OK, this);
            } else {
//                GPR_ASSERT(status_ == FINISH);
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }
        }

    private:
        // The means of communication with the gRPC runtime for an asynchronous
        // server.
        cyberprobe::EventStream::AsyncService* service_;
        // The producer-consumer queue where for asynchronous server notifications.
        ServerCompletionQueue* cq_;
        // Context for the rpc, allowing to tweak aspects of it such as the use
        // of compression, authentication, as well as to send metadata back to the
        // client.
        ServerContext ctx_;

        // What we get from the client.
        Event request_;
        // What we send back to the client.
        Empty reply_;

        // The means to get back to the client.
        ServerAsyncResponseWriter<Empty> responder_;

        // Let's implement a tiny state machine with the following states.
        enum CallStatus { CREATE, PROCESS, FINISH };
        CallStatus status_;  // The current serving state.
    };

    // This can be run in multiple threads if needed.
    void HandleRpcs() {
        // Spawn a new CallData instance to serve new clients.
        new CallData(&service_, cq_.get());
        void* tag;  // uniquely identifies a request.
        bool ok;
        while (true) {
            // Block waiting to read the next event from the completion queue. The
            // event is uniquely identified by its tag, which in this case is the
            // memory address of a CallData instance.
            // The return value of Next should always be checked. This return value
            // tells us whether there is any kind of event or cq_ is shutting down.
            GPR_ASSERT(cq_->Next(&tag, &ok));
//            GPR_ASSERT(ok);
            static_cast<CallData*>(tag)->Proceed();
        }
    }

    std::unique_ptr<ServerCompletionQueue> cq_;
    cyberprobe::EventStream::AsyncService service_;
    std::unique_ptr<Server> server_;
};

int main(int argc, char** argv) {
    ServerImpl server;
    server.Run();

    return 0;
}






/*
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

void run() {

std::string server_address("0.0.0.0:50051");
EventStreamServiceImpl service;

ServerBuilder builder;

// Listen on the given address without any authentication mechanism.
builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

// Register "service" as the instance through which we'll communicate with
// clients. In this case it corresponds to an *synchronous* service.
builder.RegisterService(&service);

// Get hold of the completion queue used for the asynchronous communication
// with the gRPC runtime.
cq_ = builder.AddCompletionQueue();

// Finally assemble the server.
std::unique_ptr<Server> server(builder.BuildAndStart());
std::cout << "Server listening on " << server_address << std::endl;

// Wait for the server to shutdown. Note that some other thread must be
// responsible for shutting down the server for this call to ever return.
server->Wait();

}
    
};

int main(int argc, char** argv) {

run();
return 0;

}

*/

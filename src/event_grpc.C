
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cybermon/event.h>
#include <cybermon/cybermon-lua.h>

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "cyberprobe.grpc.pb.h"

using grpc::Channel;
using grpc::ChannelInterface;
using grpc::ClientContext;
using grpc::Status;
using cyberprobe::Event;
using cyberprobe::Empty;
using cyberprobe::EventStream;
using grpc::ClientAsyncResponseReader;
using grpc::CompletionQueue;

namespace cybermon {

    class eventstream_client {

    public:

        explicit eventstream_client(std::shared_ptr<Channel> channel)
            : stub(cyberprobe::EventStream::NewStub(channel)), running(true) {}

        std::thread thr;

        void shutdown() {
            running = false;
            // FIXME: Shutdown completion queue here?
            thr.join();
        }

        // Assembles the client's payload and sends it to the server.
        void observe(std::shared_ptr<cybermon::event::event> ev) {

            // Data we are sending to the server.
            cyberprobe::Event request;
            ev->to_protobuf(request);

            // Call object to store rpc data
            AsyncClientCall* call = new AsyncClientCall;

            // Create RPC object.
            call->response_reader =
                stub->PrepareAsyncObserve(&call->context, request, &cq);

            // StartCall initiates the RPC call
            call->response_reader->StartCall();

            // Request that, upon completion of the RPC, "reply" be updated with the
            // server's response; "status" with the indication of whether the operation
            // was successful. Tag the request with the memory address of the
            // call object.
            call->response_reader->Finish(&call->reply, &call->status, (void*)call);

        }

        // Loop while listening for completed responses.
        // Prints out the response from the server.
        void async_complete() {

            void* got_tag;
            bool ok = false;

            // Block until the next result is available in the completion queue "cq".
            while (running && cq.Next(&got_tag, &ok)) {

                // The tag in this example is the memory location of the call object
                AsyncClientCall* call = static_cast<AsyncClientCall*>(got_tag);

                // Verify that the request was completed successfully. Note that "ok"
                // corresponds solely to the request for updates introduced by Finish().
                GPR_ASSERT(ok);

//            if (call->status.ok())
//                std::cout << "Client received." << std::endl;
//            else
//                std::cout << "RPC failed" << std::endl;

                // Once we're complete, deallocate the call object.
                delete call;
            }
        }

        void start_async() {
            thr = std::thread(&eventstream_client::async_complete, this);
        }

    private:

        // struct for keeping state and data information
        struct AsyncClientCall {

            // Container for the data we expect from the server.
            Empty reply;

            // Context for the client. It could be used to convey extra information to
            // the server and/or tweak certain RPC behaviors.
            ClientContext context;

            // Storage for the status of the RPC upon completion.
            Status status;

            std::unique_ptr<ClientAsyncResponseReader<Empty>> response_reader;

        };

        // Out of the passed in Channel comes the stub, stored here, our view of the
        // server's exposed services.
        std::unique_ptr<cyberprobe::EventStream::Stub> stub;

        // The producer-consumer queue we use to communicate asynchronously with the
        // gRPC runtime.
        CompletionQueue cq;
    
        bool running;

    };

    std::shared_ptr<grpc_manager> grpc_manager::create() {
        return std::make_shared<grpc_manager>();
    }

    void grpc_manager::observe(std::shared_ptr<event::event> ev,
                               const std::string& svc) {

        if (client.count(svc) == 0) {

            std::cerr << "Connecting gRPC to " << svc << std::endl;
    
            auto chan = grpc::CreateChannel(svc,
                                            grpc::InsecureChannelCredentials());
            auto cli = std::make_shared<eventstream_client>(chan);
            client[svc] = cli;

            cli->start_async();
    
        }

        client[svc]->observe(ev);

    }

    void grpc_manager::close() {

        // Destructors will sort everything.
        for(auto it = client.begin(); it != client.end(); it++) {
            it->second->shutdown();
        }
        client.clear();
    }

    grpc_manager::~grpc_manager() {
    }

}


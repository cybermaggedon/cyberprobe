
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>

#include <cyberprobe/event/event.h>
#include <cyberprobe/analyser/grpc.h>

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

using cyberprobe::analyser::grpc_manager;

namespace cyberprobe {

namespace analyser {

    class eventstream_client {

    public:

        explicit eventstream_client(std::shared_ptr<Channel> channel)
            : stub(cyberprobe::EventStream::NewStub(channel)),
              running(true), outstanding(0), retry_time(0) {}

        std::thread async_thread;
        std::thread retry_thread;

        void shutdown() {

            running = false;

            std::unique_lock<std::mutex> lock(mutex);
            while(outstanding > 0) {
                cond.wait(lock);
            }
            lock.unlock();

            cq.Shutdown();

            retry_thread.join();
            async_thread.join();
        }

        // Assembles the client's payload and sends it to the server.
        void observe(std::shared_ptr<cyberprobe::event::event> ev) {

            // Call object to store rpc data
            async_call* call = new async_call;

            // Marshal to protobuf event
            ev->to_protobuf(call->request);

            // Create RPC object.
            call->response_reader =
                stub->PrepareAsyncObserve(&call->context, call->request, &cq);

            {
                std::unique_lock<std::mutex> lock(mutex);

                while(outstanding >= max_outstanding) {
                    cond.wait(lock);
                }

                outstanding++;

            }

            // StartCall initiates the RPC call
            call->response_reader->StartCall();

            // Request that, upon completion of the RPC, "reply" be updated
            // with the server's response; "status" with the indication of
            // whether the operation was successful. Tag the request with the
            // memory address of the call object.
            call->response_reader->Finish(&call->reply, &call->status,
                                          (void*)call);

        }

        void async_complete();
        void retry();

        void start_async() {
            async_thread = std::thread(&eventstream_client::async_complete,
                                       this);
            retry_thread = std::thread(&eventstream_client::retry, this);
        }

    private:

        // struct for keeping state and data information
        struct async_call {

            // Data we are sending to the server.
            cyberprobe::Event request;

            // Container for the data we expect from the server.
            Empty reply;

            // Context for the client. It could be used to convey extra
            // information to the server and/or tweak certain RPC behaviors.
            ClientContext context;

            // Storage for the status of the RPC upon completion.
            Status status;

            std::unique_ptr<ClientAsyncResponseReader<Empty>> response_reader;

        };

        // Out of the passed in Channel comes the stub, stored here, our view
        // of the server's exposed services.
        std::unique_ptr<cyberprobe::EventStream::Stub> stub;

        // The producer-consumer queue we use to communicate asynchronously
        // with the gRPC runtime.
        CompletionQueue cq;
    
        bool running;

        // Mutex and condition on items outstanding
        std::mutex mutex;
        std::condition_variable cond;

        // Items outstanding includes items in the retry queue.
        const int max_outstanding = 10000;
        int outstanding;

        int retry_time;

        std::queue<async_call*> retry_queue;

    };

    void eventstream_client::async_complete()
    {

        // Loop while listening for completed responses.
        // Prints out the response from the server.
            
        void* got_tag;
        bool ok = false;

        // Block until the next result is available in the completion
        // queue.
        std::unique_lock<std::mutex> lock(mutex);
        while (running || (outstanding > 0)) {
            
            lock.unlock();
            
            if (!cq.Next(&got_tag, &ok)) {
                // Because we unlock out of the loop.
                lock.lock();
                break;
            }
            
            // The tag in this example is the memory location of the call
            // object
            async_call* call = static_cast<async_call*>(got_tag);
            
            // Verify that the request was completed successfully. Note
            // that "ok" corresponds solely to the request for updates
            // introduced by Finish().
//            GPR_ASSERT(ok);

            if (!call->status.ok()) {

                if (retry_time < 500000)
                    retry_time += 100000;

                retry_queue.push(call);
                
                lock.lock();
                continue;
            }

            retry_time = 0;
            
            lock.lock();
            outstanding--;
            cond.notify_all();
            
            // Once we're complete, deallocate the call object.
            delete call;
        }
        
        lock.unlock();
        
    }

    void eventstream_client::retry()
    {

        // Loop while listening for completed responses.
        // Prints out the response from the server.
        
        // Block until the next result is available in the completion
        // queue.
        std::unique_lock<std::mutex> lock(mutex);
        while (running || (outstanding > 0)) {

            if (!retry_queue.empty()) {

                async_call* call = retry_queue.front();
                retry_queue.pop();
                lock.unlock();

                if (retry_time > 0) {
                    usleep(retry_time);
                }

                // StartCall initiates the RPC call
                async_call* call2 = new async_call;

                call2->request = call->request;
                delete call;

                call2->response_reader =
                    stub->PrepareAsyncObserve(&call2->context, call2->request,
                                              &cq);
                call2->response_reader->StartCall();
                call2->response_reader->Finish(&call2->reply, &call2->status,
                                              (void*)call2);

            } else {

                lock.unlock();
                usleep(100000);

            }

            lock.lock();

        }

        lock.unlock();

    }

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

        // Shut down outstanding clients, which will results in waiting for
        // all events to be delivered.
        for(auto it = client.begin(); it != client.end(); it++) {
            it->second->shutdown();
        }
        client.clear();

    }

    grpc_manager::~grpc_manager() {
    }

}

}


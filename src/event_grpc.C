
#include <cybermon/event.h>
#include <cybermon/cybermon-lua.h>

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "cyberprobe.grpc.pb.h"

using namespace cybermon::event;
using grpc::Channel;
using grpc::ChannelInterface;
using grpc::ClientContext;
using grpc::Status;
using cyberprobe::Event;
using cyberprobe::Empty;
using cyberprobe::EventStream;

class EventStreamClient {
public:
    EventStreamClient(std::shared_ptr<ChannelInterface> channel)
        : stub_(EventStream::NewStub(channel)) {}

    // Assembles the client's payload, sends it and presents the response back
    // from the server.
    void observe(std::shared_ptr<event> ev) {

        // Data we are sending to the server.
        cyberprobe::Event request;

        ev->to_protobuf(request);
        
        // Container for the data we expect from the server.
        Empty reply;

        // Context for the client. It could be used to convey extra
        // information to the server and/or tweak certain RPC behaviors.
        ClientContext context;
        
        // The actual RPC.
        Status status = stub_->Observe(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
            return;
        } else {
            throw std::runtime_error(
                "Exception: " + status.error_message()
            );
        }
    }

private:
    std::unique_ptr<EventStream::Stub> stub_;
};

static bool inited = false;

static EventStreamClient* client;

void init() {

    client = new EventStreamClient(
        grpc::CreateChannel("localhost:50051",
                            grpc::InsecureChannelCredentials()));
    std::cerr << "Client created." << std::endl;

}

int event::lua_grpc(lua_State* lua) {

    void* ud = luaL_checkudata(lua, 1, "cybermon.event");
    luaL_argcheck(lua, ud != NULL, 1, "`event' expected");
    cybermon::event_userdata* ed =
        reinterpret_cast<cybermon::event_userdata*>(ud);

    if (inited == false) {
        init();
        inited = true;
    }

    client->observe(ed->event);
    
//    std::string pb;
//    ed->event->to_protobuf(pb);

    return 0;

}


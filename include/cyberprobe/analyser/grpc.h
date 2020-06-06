
////////////////////////////////////////////////////////////////////////////
//
// gRPC stuff
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERPROBE_ANALYSER_GRPC_H
#define CYBERPROBE_ANALYSER_GRPC_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <cyberprobe/event/event.h>

namespace cyberprobe {

namespace analyser {

#ifdef WITH_GRPC

    class eventstream_client;

    class grpc_manager {
    public:
        grpc_manager() {}
        std::map<std::string, std::shared_ptr<eventstream_client> > client;
        static std::shared_ptr<grpc_manager> create();
        void observe(std::shared_ptr<event::event>, const std::string& svc);
        void close();
        virtual ~grpc_manager();
    };

#endif

}

}

#endif

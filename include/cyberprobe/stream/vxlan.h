
/****************************************************************************

VXLAN reception support.

****************************************************************************/

#ifndef CYBERPROBE_VXLAN_H
#define CYBERPROBE_VXLAN_H

#include <cyberprobe/network/socket.h>
#include <cyberprobe/analyser/monitor.h>

#include <thread>

namespace cyberprobe {

    namespace vxlan {

        // VXLAN server.
        class receiver {

        private:
            bool running;
            analyser::monitor& mon;
            
            std::shared_ptr<tcpip::udp_socket> svr;
	    std::thread* thr;

        public:

            std::string device;

            receiver(int port, analyser::monitor& mon) : mon(mon) {
                running = true;
                std::shared_ptr<tcpip::udp_socket> sock(new tcpip::udp_socket);
                svr = sock;
                svr->bind(port);
		thr = nullptr;
            }

            receiver(std::shared_ptr<tcpip::udp_socket> s,
                     analyser::monitor& mon) :
                mon(mon)
                {
                    running = true;
                    svr = s;
                    thr = nullptr;
                }

            virtual ~receiver() {}
            virtual void run();

	    // Boot thread.
	    void start() {
		thr = new std::thread(&receiver::run, this);
	    }

	    virtual void join() {
		if (thr)
		    thr->join();
	    }

	    virtual void stop() {
		running = false;
	    }

        };

    };

};

#endif


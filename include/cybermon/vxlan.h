
/****************************************************************************

VXLAN reception support.

****************************************************************************/

#ifndef CYBERMON_VXLAN_H
#define CYBERMON_VXLAN_H

#include <cybermon/socket.h>
#include <cybermon/monitor.h>

#include <thread>

namespace cybermon {

    namespace vxlan {

        // VXLAN server.
        class receiver {

          private:
            bool running;
            monitor& mon;
            
            std::shared_ptr<tcpip::udp_socket> svr;
	    std::thread* thr;

          public:

            receiver(int port, monitor& mon) : mon(mon) {
                running = true;
                std::shared_ptr<tcpip::udp_socket> sock(new tcpip::udp_socket);
                svr = sock;
                svr->bind(port);
		thr = nullptr;
            }

            receiver(std::shared_ptr<tcpip::udp_socket> s, monitor& mon)
                : mon(mon)
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


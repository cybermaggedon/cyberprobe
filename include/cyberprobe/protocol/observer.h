
#ifndef CYBERMON_OBSERVER_H
#define CYBERMON_OBSERVER_H

#include <vector>
#include <memory>

namespace cyberprobe {

    namespace event {
        class event;
    }

    namespace protocol {

        // Observer interface.  The observer interface is called when various
        // reportable events occur.
        class observer {
        public:
            virtual void handle(std::shared_ptr<event::event>) = 0;
        };

    }

}

#endif

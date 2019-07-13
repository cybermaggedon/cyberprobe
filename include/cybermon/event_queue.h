
#ifndef EVENT_QUEUE_H
#define EVENT_QUEUE_H

#include <queue>
#include <thread>
#include <condition_variable>
#include <cstddef>

#include <cybermon/event.h>

namespace cybermon {

    namespace event {

        class observer {
        public:
            virtual void handle(std::shared_ptr<event>) = 0;
        };

        class basic_queue {
        public:
            typedef std::shared_ptr<event> eptr;
            virtual void push(eptr e) = 0;
        };
        
        class queue : public basic_queue {
        
        private:
            std::queue<eptr> q;
            std::mutex mutex;
            std::condition_variable cond;

        public:

            void stop() {
                push(std::shared_ptr<cybermon::event::event>(nullptr));
            }
            
            queue() {}
            virtual ~queue() {}

            virtual void push(eptr e) {
                std::lock_guard<std::mutex> lock(mutex);
                q.push(e);
                cond.notify_one();
            }

            // Reader body.
            virtual void run(observer& o) {
                
                std::unique_lock<std::mutex> lock(mutex);

                // Loop until finished.
                while (true) {

                    // Have lock at this point.

                    while (q.size() < 1)
                        cond.wait(lock);
                    
                    // Take next packet off queue.
                    eptr e = q.front();
                    q.pop();

                    // Null pointer indicates end of stream.
                    if (!e) {
                        lock.unlock();
                        break;
                    }
                    
                    // Got the packet, so the queue can unlock.
                    lock.unlock();

                    try {
                        o.handle(e);
                    } catch (std::exception& e) {
                        std::cerr << "event exception: " << e.what()
                                  << std::endl;
                    }

                    // Get the lock.
                    lock.lock();

                }

            }

        };

    };

};

#endif /* EVENT_QUEUE_H */

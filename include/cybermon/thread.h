
/****************************************************************************

  File: thread.h

  Provides multi-threaded execution support.

  Example:

    class thing : public thread::thread {
	void run() {
	    for(int i = 0; i < 4; i++) {
		std::cout << i << std::endl;
		sleep(1);
	    }
	}
    };

    thing t;
    t.start();

****************************************************************************/

#ifndef CYBERMON_THREAD_H
#define CYBERMON_THREAD_H

#include <stdexcept>
#include <pthread.h>

/** Thread namespace */
namespace threads {

    /** Thread class. */
    class thread {
      private:

	/** Pthread id */
	pthread_t thr;
      public:

	thread() { }

	/** Destructor does nothing - you should pthread_join to reap the 
	    thread before destroying. */
	virtual ~thread() { }

	/** Thread body.  Over-ride to make the thread useful. */
	virtual void run() {
	}

	/** Start execution of the thread body in a separate thread. */
	void start() {
	    int ret = pthread_create(&thr, 0, &do_start, 
				     static_cast<void*>(this));
	    if (ret < 0)
		throw std::runtime_error("Couldn't start thread.");

	}

	/** If running, wait for thread execution to stop. */
	void join() {
	    int ret = pthread_join(thr, 0);
	    if (ret < 0)
		throw std::runtime_error("Couldn't join thread.");
	}

      private:

	/** A boot-strap, bridges pthread and thread::thread API. */
	static void* do_start(void* arg) {
	    thread* t = static_cast<thread*>(arg);
	    t->run();
	    return 0;
	}

      private:

    };

    class condition;

    class mutex {
	friend class condition;
      private:
	pthread_mutex_t lk;
      public:
	mutex() { pthread_mutex_init(&lk, 0); }
	virtual ~mutex() { pthread_mutex_destroy(&lk); }
	void lock() { pthread_mutex_lock(&lk); }
	void unlock() { pthread_mutex_unlock(&lk); }
    };

    class condition {
      private:
	pthread_cond_t cond;
      public:
	condition() { pthread_cond_init(&cond, 0); }
	virtual ~condition() { pthread_cond_destroy(&cond); }
	void wait(mutex& m) {
	    pthread_cond_wait(&cond, &(m.lk));
	}

	void broadcast() {
	    pthread_cond_broadcast(&cond);
	}
	
	void signal() {
	    pthread_cond_signal(&cond);
	}
	
    };

};

#endif


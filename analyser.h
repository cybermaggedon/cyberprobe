
#ifndef ANALYSER_H
#define ANALYSER_H

#include <string>
#include <vector>
#include <list>
#include <map>

#include "thread.h"
#include "pdu.h"
#include "context.h"

namespace analyser {

    class observer {
    public:
	virtual void data(const context_ptr cp, const pdu_iter& s, 
			  const pdu_iter& e) = 0;
    };

    class engine : public observer {
      private:

	threads::mutex lock;
	std::map<std::string, context_ptr> contexts;

      public:

	engine() { }
	virtual ~engine() {}

	context_ptr get_root_context(const std::string& liid);
	void close_root_context(const std::string& liid);

	void process(context_ptr c, const pdu_iter& s, const pdu_iter& e);

	static void get_context_stack(context_ptr p, std::list<context_ptr>& l) {
	    while (p) {
		l.push_front(p);
		p = p->parent.lock();
	    }
	}

	static void get_root_info(context_ptr p,
				  std::string& liid,
				  address& ta);
	
	static void get_network_info(context_ptr p,
				     address& src, address& dest);
	
	static void describe(context_ptr p, std::ostream& out);
	
    };

};

#endif


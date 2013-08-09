
#ifndef ANALYSER_H
#define ANALYSER_H

#include <string>
#include <vector>
#include <list>
#include <map>

#include "thread.h"

namespace analyser {

    class context {
      public:
	unsigned long id;
	std::string liid;
    };
    
    class engine {
      private:

	unsigned long next_context_id;
	threads::mutex lock;
	std::map<unsigned long, context> contexts;

      public:

	engine() { next_context_id = 0; }
	virtual ~engine() {}
	
	context& create_context(const std::string& liid);
	void destroy_context(context&);

	typedef std::vector<unsigned char>::iterator iter;
	void process(context& c, const iter& s, const iter& e);
	
	void process(context& c, const iter& s, const iter& e, 
		     const std::string& state);
	
    };

};

#endif


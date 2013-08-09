
#include "thread.h"

#include "analyser.h"

using namespace analyser;

context& engine::create_context(const std::string& liid)
{
    lock.lock();
    unsigned long id = next_context_id++;
    contexts[id].id = id;
    contexts[id].liid = liid;
    context& c = contexts[id];
    lock.unlock();
    return c;
}

void engine::destroy_context(context& c)
{
    lock.lock();
    contexts.erase(c.id);
    lock.unlock();
}

void engine::process(context& c, const engine::iter& s, const engine::iter& e)
{
    const std::string state = "ip";
    process(c, s, e, state);
}

void engine::process(context& c, const engine::iter& s, const engine::iter& e, 
		     const std::string& state)
{
}


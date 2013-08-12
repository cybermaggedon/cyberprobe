
#include "thread.h"
#include "context.h"
#include "analyser.h"
#include "ip.h"

using namespace analyser;

context_ptr engine::get_root_context(const std::string& liid)
{
    lock.lock();

    context_ptr c;

    if (contexts.find(liid) == contexts.end()) {
	c = target_context::create(liid);
	contexts[liid] = c;
    } else
	c = contexts[liid];

    lock.unlock();

    return c;
}

void engine::process(context_ptr c, const pdu_iter& s, const pdu_iter& e)
{
    ip::process(*this, c, s, e);
}

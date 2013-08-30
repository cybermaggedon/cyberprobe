
#include "address.h"
#include "smtp.h"
#include "ctype.h"
#include "manager.h"
#include "hexdump.h"

#include <iostream>

using namespace cybermon;

// SMTP client processing function.
void smtp::process_client(manager& mgr, context_ptr c, 
			  pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, SMTP);
    dest.set(empty, TRANSPORT, SMTP);

    flow_address f(src, dest);

    smtp_client_context::ptr fc = smtp_client_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	hexdump::dump(s, e, std::cout);
//	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

// SMTP server processing function.
void smtp::process_server(manager& mgr, context_ptr c, 
			  pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, SMTP);
    dest.set(empty, TRANSPORT, SMTP);

    flow_address f(src, dest);

    smtp_server_context::ptr fc = smtp_server_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	hexdump::dump(s, e, std::cout);
//	fc->parse(fc, s, e, mgr);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

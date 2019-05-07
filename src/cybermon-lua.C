
#include <sstream>

#include <cybermon/cybermon-lua.h>
#include <cybermon/forgery.h>
#include <cybermon/pdu.h>

using namespace cybermon;

cybermon_lua::cybermon_lua(const std::string& cfg)
{

    // Add configuration file's directory to package.path.
    add_parent_directory_path(cfg);

    // Load the configuration file.
    load_module(cfg);

    // Transfer result from module to global variable 'config'.
    set_global("config");

    // Put new meta-table on the stack.
    new_meta_table("cybermon.context");

    push("__index");
    push_value(-2);       /* pushes the metatable */
    set_table(-3);  /* metatable.__index = metatable */
    
    std::map<std::string,lua_CFunction> afns;
    afns["__gc"] = &context_gc;
    afns["get_type"] = &context_get_type;
    afns["get_parent"] = &context_get_parent;
    afns["get_src_addr"] = &context_get_src_addr;
    afns["get_dest_addr"] = &context_get_dest_addr;
    afns["get_reverse"] = &context_get_reverse;
    afns["get_id"] = &context_get_id;
    afns["describe_src"] = &context_describe_src;
    afns["describe_dest"] = &context_describe_dest;
    afns["get_liid"] = &context_get_liid;
    afns["get_context_id"] = &context_get_id;
    afns["get_network_info"] = &context_get_network_info;
    afns["get_trigger_info"] = &context_get_trigger_info;
    afns["forge_dns_response"] = &context_forge_dns_response;
    afns["forge_tcp_reset"] = &context_forge_tcp_reset;
    afns["forge_tcp_data"] = &context_forge_tcp_data;
    afns["get_creation_time"] = &context_get_creation_time;
    afns["get_direction"] = &context_get_direction;

    register_table(afns);

    // Pop meta-table
    pop();

}

// Call the config.trigger_up function as trigger_up(event)
void cybermon_lua::trigger_up(const std::string& liid, const std::string& a,
			      const timeval& time)
{
 
    // Get information stored about the attacker.
    /*std::string ta;
    a.to_string(ta);*/
    // Get config.trigger_up
    get_global("config");
    get_field(-1, "trigger_up");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table device.
    push("device");
    push(liid);
    set_table(-3);

    // Set table address
    push("address");
    push(a);
    set_table(-3);
	
    // config.trigger_up(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}

// Call the config.trigger_down function as trigger_down(event)
void cybermon_lua::trigger_down(const std::string& liid,
				const timeval& time)
{

    // Get config.trigger_down
    get_global("config");
    get_field(-1, "trigger_down");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table device.
    push("device");
    push(liid);
    set_table(-3);
	
    // config.trigger_down(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.connection_up function as connection_up(event)
// The 'context' variable passed to LUA is a userdata pointer,
// allowing calling back into the C++ code.
void cybermon_lua::connection_up(engine& an, context_ptr f, const timeval& time)
{

    // Get config.connection_up
    get_global("config");
    get_field(-1, "connection_up");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // config.connection_up(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.connection_down function as connection_down(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::connection_down(engine& an, const context_ptr f,
				   const timeval& time)
{
    
    // Get config.connection_down
    get_global("config");
    get_field(-1, "connection_down");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // config.connection_down(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.unreognised_stream function as
// unrecognised_stream(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::unrecognised_stream(engine& an, const context_ptr f, 
				       pdu_iter s, pdu_iter e,
				       const timeval& time, int64_t posn)
{
    
    // Get config.unrecognised_stream
    get_global("config");
    get_field(-1, "unrecognised_stream");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);
    
    // Put data on stack.
    push("position");
    push(posn);
    set_table(-3);
    
    // config.unrecognised_stream(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.unrecognised_datagram function as
// unrecognised_datagram(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::unrecognised_datagram(engine& an, 
					 const context_ptr f, 
					 pdu_iter s, 
					 pdu_iter e,
					 const timeval& time)
{
    
    // Get config.unrecognised_datagram
    get_global("config");
    get_field(-1, "unrecognised_datagram");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);
    
    // config.unrecognised_datagram(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}


void cybermon_lua::icmp(engine& an, const context_ptr f, unsigned int type,
			unsigned int code, pdu_iter s, pdu_iter e,
			const timeval& time)
{

    // Get config.icmp
    get_global("config");
    get_field(-1, "icmp");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Set table type and code
    push("type");
    push(type);
    set_table(-3);
    push("code");
    push(code);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);
    
    // config.icmp(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}


void cybermon_lua::imap(engine& an, const context_ptr f,
			pdu_iter s, pdu_iter e, const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "imap");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}


void cybermon_lua::imap_ssl(engine& an, const context_ptr f,
                            pdu_iter s, pdu_iter e, const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "imap_ssl");


    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}


void cybermon_lua::pop3(engine& an, const context_ptr f,
			pdu_iter s, pdu_iter e, const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "pop3");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}


void cybermon_lua::pop3_ssl(engine& an, const context_ptr f,
                            pdu_iter s, pdu_iter e,
			    const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "pop3_ssl");


    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
	call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}


void cybermon_lua::rtp(engine& an, const context_ptr f,
		       pdu_iter s, pdu_iter e,
		       const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "rtp");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::rtp_ssl(engine& an, const context_ptr f,
			   pdu_iter s, pdu_iter e,
			   const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "rtp_ssl");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::sip_request(engine& an,
			       const context_ptr f,
			       const std::string& method,
			       const std::string& from,
			       const std::string& to,
			       pdu_iter s,
			       pdu_iter e,
			       const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "sip_request");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push 'method'
    push("method");
    push(method);
    set_table(-3);

    // Push 'from'
    push("from");
    push(from);
    set_table(-3);

    // Push 'to'
    push("to");
    push(to);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}


void cybermon_lua::sip_response(engine& an,
                                const context_ptr f,
                                unsigned int code,
                                const std::string& status,
                                const std::string& from,
                                const std::string& to,
                                pdu_iter s,
                                pdu_iter e,
				const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "sip_response");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push 'code'
    push("code");
    push(code);
    set_table(-3);
   

    // Push 'status'
    push("status");
    push(status);
    set_table(-3);

    // Push 'from'
    push("from");
    push(from);
    set_table(-3);

    // Push 'to'
    push("to");
    push(to);
    set_table(-3);

    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::sip_ssl(engine& an,
                           const context_ptr f,
                           pdu_iter s,
                           pdu_iter e,
			   const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "sip_ssl");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::smtp_auth(engine& an,
                             const context_ptr f,
                             pdu_iter s,
                             pdu_iter e,
			     const timeval& time)
{
    // Get config
    get_global("config");
    get_field(-1, "smtp_auth");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Put data on stack.
    push("data");
    push(s, e);
    set_table(-3);

    try
    {
        call(1, 0);
    }
    catch (std::exception& e)
    {
        pop();
        throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}


void cybermon_lua::http_request(engine& an, const context_ptr f,
				const std::string& method,
				const std::string& url,
				const http_header& hdr,
				pdu_iter s,
				pdu_iter e,
				const timeval& time)
{

    // Get config.http_request
    get_global("config");
    get_field(-1, "http_request");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // Push method
    push("method");
    push(method);
    set_table(-3);

    // Push URL
    push("url");
    push(url);
    set_table(-3);

    // Build header table on stack.
    push("header");
    create_table(0, hdr.size());

    // Loop through header
    for(http_header::const_iterator it = hdr.begin();
	it != hdr.end();
	it++) {

	// Set table row.
	push(it->second.first);
	push(it->second.second);
	set_table(-3);

    }
    set_table(-3);

    // Put data on stack.
    push("body");
    push(s, e);
    set_table(-3);

    // config.http_request(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::http_response(engine& an, const context_ptr f,
				 unsigned int code,
				 const std::string& status,
				 const http_header& hdr,
				 const std::string& url,
				 pdu_iter s,
				 pdu_iter e,
				 const timeval& time)
{

    // Get config.http_response
    get_global("config");
    get_field(-1, "http_response");
    
    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    

    // Push code
    push("code");
    push(code);
    set_table(-3);

    // Push status
    push("status");
    push(status);
    set_table(-3);

    // Build header table on stack.
    push("header");
    create_table(0, hdr.size());

    // Loop through header
    for(http_header::const_iterator it = hdr.begin();
	it != hdr.end();
	it++) {

	// Set table row.
	push(it->second.first);
	push(it->second.second);
	set_table(-3);

    }
    set_table(-3);

    // Push fully normalised URL if known.
    push("url");
    push(url);
    set_table(-3);

    // Put data on stack.
    push("body");
    push(s, e);
    set_table(-3);

    // config.http_response(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::smtp_command(engine& an, const context_ptr f,
				const std::string& command,
				const timeval& time)
{

    // Get config.smtp_command
    get_global("config");
    get_field(-1, "smtp_command");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push method
    push("command");
    push(command);
    set_table(-3);

    // config.smtp_command(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::smtp_response(engine& an, const context_ptr f,
				 int status,
				 const std::list<std::string>& text,
				 const timeval& time)
{

    // Get config.smtp_response
    get_global("config");
    get_field(-1, "smtp_response");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push method
    push("status");
    push(status);
    set_table(-3);

    // Build texts table on stack.
    push("text");
    create_table(0, text.size());

    // Loop through header
    int row = 1;
    for(std::list<std::string>::const_iterator it = text.begin();
	it != text.end();
	it++) {

	// Set table row.
	push(row++);
	push(*it);
	set_table(-3);

    }
    set_table(-3);

    // config.smtp_response(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::smtp_data(engine& an, const context_ptr f,
			     const std::string& from,
			     const std::list<std::string>& to,
			     pdu_iter s, pdu_iter e,
			     const timeval& time)
{

    // Get config.http_request
    get_global("config");
    get_field(-1, "smtp_data");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push from.
    push("from");
    push(from);
    set_table(-3);

    // Build to table on stack.
    push("to");
    create_table(0, to.size());

    // Loop through 'to'
    int row = 1;
    for(std::list<std::string>::const_iterator it = to.begin();
	it != to.end();
	it++) {

	// Set table row.
	push(row++);
	push(*it);
	set_table(-3);

    }
    set_table(-3);

    // Push data.
    push("data");
    push(s, e);
    set_table(-3);

    // config.smtp_data(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::ftp_command(engine& an, const context_ptr f,
			       const std::string& command,
			       const timeval& time)
{

    // Get config.http_request
    get_global("config");
    get_field(-1, "ftp_command");
    
    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push method
    push("command");
    push(command);
    set_table(-3);

    // config.ftp_command(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::ftp_response(engine& an, const context_ptr f,
				int status,
				const std::list<std::string>& text,
				const timeval& time)
{

    // Get config.ftp_request
    get_global("config");
    get_field(-1, "ftp_response");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    // Push method
    push("status");
    push(status);
    set_table(-3);

    // Build texts table on stack.
    push("text");
    create_table(0, text.size());

    // Loop through header
    int row = 1;
    for(std::list<std::string>::const_iterator it = text.begin();
	it != text.end();
	it++) {

	// Set table row.
	push(row++);
	push(*it);
	set_table(-3);

    }
    set_table(-3);

    // config.ftp_response(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::dns_message(engine& an,
			       const context_ptr f,
			       const dns_header& hdr, 
			       const std::list<dns_query> queries,
			       const std::list<dns_rr> answers,
			       const std::list<dns_rr> authorities,
			       const std::list<dns_rr> additional,
			       const timeval& time)
{

    // Get config.dns_over_udp_message
    get_global("config");
    get_field(-1, "dns_message");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    push("header");
    push(hdr);
    set_table(-3);

    push("queries");
    push(queries);
    set_table(-3);

    push("answers");
    push(answers);
    set_table(-3);

    push("authorities");
    push(authorities);
    set_table(-3);

    push("additional");
    push(additional);
    set_table(-3);

    try
    {
	call(1, 0);
    }
    catch (std::exception& e)
    {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::ntp_timestamp_message(engine& an, const context_ptr f,
					 const ntp_timestamp& ts,
					 const timeval& time)
{
    // Get config.ntp_timestamp_message
    get_global("config");
    get_field(-1, "ntp_timestamp_message");
    

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    push("header");
    push(ts.m_hdr);
    set_table(-3);

    push("timestamp");
    push(ts);
    set_table(-3);
   
    // config.ntp_timestamp_message(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::ntp_control_message(engine& an, const context_ptr f,
				       const ntp_control& ctrl,
				       const timeval& time)
{
    // Get config.ntp_control_message
    get_global("config");
    get_field(-1, "ntp_control_message");

    
    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    push("header");
    push(ctrl.m_hdr);
    set_table(-3);

    push("control");
    push(ctrl);
    set_table(-3);
   
    // config.ntp_control_message(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::ntp_private_message(engine& an, const context_ptr f,
				       const ntp_private& priv,
				       const timeval& time)
{
    // Get config.ntp_private_message
    get_global("config");
    get_field(-1, "ntp_private_message");
    
    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);
    
    push("header");
    push(priv.m_hdr);
    set_table(-3);

    push("private");
    push(priv);
    set_table(-3);
   
    // config.ntp_private_message(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::gre_message(engine& an,
				       const context_ptr cf,
				       const std::string& nextProto,
				       const uint32_t key,
				       const uint32_t sequenceNo,
				       pdu_iter payload_start,
				       pdu_iter payload_end,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "gre");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("next_proto");
    push(nextProto);
    set_table(-3);

    push("key");
    push(key);
    set_table(-3);

    push("sequence_number");
    push(sequenceNo);
    set_table(-3);

    push("payload");
    push(payload_start, payload_end);
    set_table(-3);

    // config.gre_message(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::gre_pptp_message(engine& an,
				       const context_ptr cf,
				       const std::string& nextProto,
				       const uint16_t payload_length,
				       const uint16_t call_id,
				       const uint32_t sequenceNo,
				       const uint32_t ackNo,
				       pdu_iter payload_start,
				       pdu_iter payload_end,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "gre_pptp");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("next_proto");
    push(nextProto);
    set_table(-3);

    push("call_id");
    push(call_id);
    set_table(-3);

    push("sequence_number");
    push(sequenceNo);
    set_table(-3);

    push("acknowledgement_number");
    push(ackNo);
    set_table(-3);

    push("payload_legnth");
    push(payload_length);
    set_table(-3);

    push("payload");
    push(payload_start, payload_end);
    set_table(-3);

    // config.gre_message(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::esp(engine& an,
				       const context_ptr cf,
				       const uint32_t spi,
				       const uint32_t sequence,
				       const uint32_t length,
				       pdu_iter start,
				       pdu_iter end,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "esp");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("spi");
    push(spi);
    set_table(-3);

    push("sequence_number");
    push(sequence);
    set_table(-3);

    push("payload_length");
    push(length);
    set_table(-3);

    push("payload");
    push(start, end);
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::unrecognised_ip_protocol(engine& an,
				       const context_ptr cf,
				       const uint8_t nxtProto,
				       const uint32_t len,
				       pdu_iter start,
				       pdu_iter end,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "unrecognised_ip_protocol");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("next_proto");
    push(nxtProto);
    set_table(-3);

    push("payload_length");
    push(len);
    set_table(-3);

    push("payload");
    push(start, end);
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::wlan(engine& an,
				       const context_ptr cf,
				       const uint8_t version,
				       const uint8_t type,
				       const uint8_t subtype,
				       const uint8_t flags,
				       const bool is_protected,
				       const uint16_t duration,
				       const std::string& filt_addr,
				       const uint8_t frag_num,
				       const uint16_t seq_num,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "wlan");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("version");
    push(version);
    set_table(-3);

    push("type");
    push(type);
    set_table(-3);

    push("subtype");
    push(subtype);
    set_table(-3);

    push("flags");
    push(flags);
    set_table(-3);

    push("protected");
    push(is_protected);
    set_table(-3);

    push("duration");
    push(duration);
    set_table(-3);

    push("filt_addr");
    push(filt_addr);
    set_table(-3);

    push("frag_num");
    push(frag_num);
    set_table(-3);

    push("seq_num");
    push(seq_num);
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls(engine& an,
				       const context_ptr cf,
               const std::string& version,
               const uint8_t contentType,
               const uint16_t length,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "tls");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("version");
    push(version);
    set_table(-3);

    push("content_type");
    push(contentType);
    set_table(-3);

    push("length");
    push(length);
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_client_hello(engine& an,
				       const context_ptr cf,
               const tls_handshake_protocol::client_hello_data& data,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "tls_client_hello");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("version");
    push(data.version);
    set_table(-3);

    push("random_timestamp");
    push(data.randomTimestamp);
    set_table(-3);

    push("random_data");
    push(std::begin(data.random), std::end(data.random));
    set_table(-3);

    push("session_id");
    push(data.sessionID);
    set_table(-3);

    push("cipher_suites");
    create_table(data.cipherSuites.size(), 0);
    int index=1;
    for (std::vector<tls_handshake_protocol::cipher_suite>::const_iterator iter=data.cipherSuites.begin();
      iter != data.cipherSuites.end();
      ++iter)
    {
      push(index);
      create_table(2,0);
      push("id");
      push(iter->id);
      set_table(-3);
      push("name");
      push(iter->name);
      set_table(-3);
      set_table(-3);
      ++index;
    }
    set_table(-3);

    push("compression_methods");
    create_table(data.compressionMethods.size(), 0);
    index=1;
    for (std::vector<tls_handshake_protocol::compression_method>::const_iterator iter=data.compressionMethods.begin();
      iter != data.compressionMethods.end();
      ++iter)
    {
      push(index);
      create_table(2,0);
      push("id");
      push(iter->id);
      set_table(-3);
      push("name");
      push(iter->name);
      set_table(-3);
      set_table(-3);
      ++index;
    }
    set_table(-3);

    push("extensions");
    create_table(data.extensions.size(), 0);
    index = 1;
    for (std::vector<tls_handshake_protocol::extension>::const_iterator iter=data.extensions.begin();
      iter != data.extensions.end();
      ++iter)
    {
      push(index);
      create_table(4,0);
      push("type");
      push(iter->type);
      set_table(-3);
      push("name");
      push(iter->name);
      set_table(-3);
      push("length");
      push(iter->len);
      set_table(-3);
      push("data");
      push(iter->data.begin(), iter->data.end());
      set_table(-3);
      set_table(-3);
      ++index;
    }
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_server_hello(engine& an,
				       const context_ptr cf,
               const tls_handshake_protocol::server_hello_data& data,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "tls_server_hello");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("version");
    push(data.version);
    set_table(-3);

    push("random_timestamp");
    push(data.randomTimestamp);
    set_table(-3);

    push("random_data");
    push(std::begin(data.random), std::end(data.random));
    set_table(-3);

    push("session_id");
    push(data.sessionID);
    set_table(-3);

    push("cipher_suite");
    create_table(2,0);
    push("id");
    push(data.cipherSuite.id);
    set_table(-3);
    push("name");
    push(data.cipherSuite.name);
    set_table(-3);
    set_table(-3);

    push("compression_method");
    create_table(2,0);
    push("id");
    push(data.compressionMethod.id);
    set_table(-3);
    push("name");
    push(data.compressionMethod.name);
    set_table(-3);
    set_table(-3);

    push("extensions");
    create_table(data.extensions.size(), 0);
    int index = 1;
    for (std::vector<tls_handshake_protocol::extension>::const_iterator iter=data.extensions.begin();
      iter != data.extensions.end();
      ++iter)
    {
      push(index);
      create_table(4,0);
      push("type");
      push(iter->type);
      set_table(-3);
      push("name");
      push(iter->name);
      set_table(-3);
      push("length");
      push(iter->len);
      set_table(-3);
      push("data");
      push(iter->data.begin(), iter->data.end());
      set_table(-3);
      set_table(-3);
      ++index;
    }
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_certificates(engine& an,
				       const context_ptr cf,
               const std::vector<std::vector<uint8_t>>& certs,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "tls_certificates");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("certificates");
    create_table(certs.size(), 0);
    int index = 1;
    for (std::vector<std::vector<uint8_t>>::const_iterator iter=certs.begin();
      iter != certs.end();
      ++iter)
    {
      push(index);
      push(std::begin(*iter), std::end(*iter));
      set_table(-3);
      ++index;
    }
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_server_key_exchange(engine& an,
				       const context_ptr cf,
               const tls_handshake_protocol::key_exchange_data& data,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "tls_server_key_exchange");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    if (data.ecdh)
    {
      push("key_exchange_algorithm");
      push("ec-dh");
      set_table(-3);

      push("curve_type");
      push(data.ecdh->curveType);
      set_table(-3);

      push("curve_metadata");
      create_table(data.ecdh->curveData.size(),0);

      for (std::vector<tls_handshake_protocol::curve_data>::const_iterator iter=data.ecdh->curveData.begin();
        iter != data.ecdh->curveData.end();
        ++iter)
      {
        push(iter->name);
        push(iter->value);
        set_table(-3);
      }
      set_table(-3); // curve metadata

      push("public_key");
      push(data.ecdh->pubKey.begin(), data.ecdh->pubKey.end());
      set_table(-3);

      push("signature_hash_algorithm");
      push(data.ecdh->sigHashAlgo);
      set_table(-3);

      push("signature_algorithm");
      push(data.ecdh->sigAlgo);
      set_table(-3);

      push("signature_hash");
      push(data.ecdh->hash.begin(), data.ecdh->hash.end());
      set_table(-3);
    }
    else if (data.dhrsa || data.dhanon)
    {
      std::shared_ptr<tls_handshake_protocol::dhanon_data> dh = data.dhrsa ? data.dhrsa : data.dhanon;

      push("key_exchange_algorithm");
      if (data.dhrsa)
      {
        push("dh-rsa");
      }
      else
      {
        push("dh-anon");
      }
      set_table(-3);

      push("prime");
      push(dh->p.begin(),dh->p.end());
      set_table(-3);

      push("generator");
      push(dh->g.begin(),dh->g.end());
      set_table(-3);

      push("pubkey");
      push(dh->pubKey.begin(),dh->pubKey.end());
      set_table(-3);

      if (data.dhrsa)
      {
        push("signature");
        push(data.dhrsa->sig.begin(), data.dhrsa->sig.end());
        set_table(-3);
      }
    }
    else
    {
      // completely empty Key exchange means its a type we dont handle
      push("key_exchange_algorithm");
      push("unhandled");
      set_table(-3);
    }

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_server_hello_done(engine& an, context_ptr f, const timeval& time)
{

    // Get config.connection_up
    get_global("config");
    get_field(-1, "tls_server_hello_done");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(f);
    set_table(-3);

    // config.connection_up(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}



void cybermon_lua::tls_handshake_generic(engine& an,
				       const context_ptr cp,
				       const uint8_t type,
				       const uint32_t len,
				       const timeval& tv)
{
  // Get config.connection_up
  get_global("config");
  get_field(-1, "tls_handshake");

  // Build event table on stack.
  create_table(0, 0);

  // Set table time.
  push("time");
  push(tv);
  set_table(-3);

  // Set table context.
  push("context");
  push(cp);
  set_table(-3);

  push("type");
  push(type);
  set_table(-3);

  push("length");
  push(len);
  set_table(-3);

  // config.connection_up(event)
  try {
call(1, 0);
  } catch (std::exception& e) {
pop();
throw;
  }

  // Still got 'config' left on stack, it can go.
  pop();
}

void cybermon_lua::tls_certificate_request(engine& an,
				       const context_ptr cf,
               const tls_handshake_protocol::certificate_request_data& data,
				       const timeval& time)
{
    // Get config.gre_message
    get_global("config");
    get_field(-1, "tls_certificate_request");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cf);
    set_table(-3);

    push("cert_types");
    create_table(data.certTypes.size(), 0);
    int index = 1;
    for (std::vector<std::string>::const_iterator iter=data.certTypes.begin();
      iter != data.certTypes.end();
      ++iter)
    {
      push(index);
      push(*iter);
      set_table(-3);
      ++index;
    }
    set_table(-3);

    push("signature_algorithms");
    create_table(data.sigAlgos.size(), 0);
    index = 1;
    for (std::vector<tls_handshake_protocol::signature_algorithm>::const_iterator iter=data.sigAlgos.begin();
      iter != data.sigAlgos.end();
      ++iter)
    {
      push(index);
      create_table(2,0);
      push("hash_algorithm");
      push(iter->sigHashAlgo);
      set_table(-3);
      push("signature_algorithm");
      push(iter->sigAlgo);
      set_table(-3);
      set_table(-3);
      ++index;
    }
    set_table(-3);

    push("distinguished_names");
    push(data.distinguishedNames.begin(),data.distinguishedNames.end());
    set_table(-3);

    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_client_key_exchange(engine& an,
				       const context_ptr cp,
				       const std::vector<uint8_t>& key,
				       const timeval& tv)
{
    // Get config.connection_up
    get_global("config");
    get_field(-1, "tls_client_key_exchange");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(tv);
    set_table(-3);

    // Set table context.
    push("context");
    push(cp);
    set_table(-3);

    push("key");
    push(key.begin(), key.end());
    set_table(-3);

    // config.connection_up(event)
    try {
call(1, 0);
    } catch (std::exception& e) {
pop();
throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();
}

void cybermon_lua::tls_certificate_verify(engine& an, const context_ptr cp, const uint8_t sigHashAlgo,
				       const uint8_t sigAlgo, const std::string& sig, const timeval& time)
{

    // Get config.connection_up
    get_global("config");
    get_field(-1, "tls_certificate_verify");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cp);
    set_table(-3);

    push("signature_algorithm");
    create_table(2,0);
    push("hash_algorithm");
    push(sigHashAlgo);
    set_table(-3);
    push("signature_algorithm");
    push(sigAlgo);
    set_table(-3);
    set_table(-3);

    // Set table context.
    push("signature");
    push(sig);
    set_table(-3);

    // config.connection_up(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::tls_change_cipher_spec(engine& an, const context_ptr cp,
				       const uint8_t val, const timeval& time)
{

    // Get config.connection_up
    get_global("config");
    get_field(-1, "tls_change_cipher_spec");

    // Build event table on stack.
    create_table(0, 0);

    // Set table time.
    push("time");
    push(time);
    set_table(-3);

    // Set table context.
    push("context");
    push(cp);
    set_table(-3);

    // Set table context.
    push("val");
    push(val);
    set_table(-3);

    // config.connection_up(event)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::tls_handshake_finished(engine& an,
				       const context_ptr cp,
				       const std::vector<uint8_t>& msg,
				       const timeval& tv)
{
  // Get config.connection_up
  get_global("config");
  get_field(-1, "tls_handshake_finished");

  // Build event table on stack.
  create_table(0, 0);

  // Set table time.
  push("time");
  push(tv);
  set_table(-3);

  // Set table context.
  push("context");
  push(cp);
  set_table(-3);

  push("msg");
  push(msg.begin(), msg.end());
  set_table(-3);

  // config.connection_up(event)
  try {
call(1, 0);
  } catch (std::exception& e) {
pop();
throw;
  }

  // Still got 'config' left on stack, it can go.
  pop();
}

void cybermon_lua::tls_handshake_complete(engine& an,
				       const context_ptr cp,
				       const timeval& tv)
{
  // Get config.connection_up
  get_global("config");
  get_field(-1, "tls_handshake_complete");

  // Build event table on stack.
  create_table(0, 0);

  // Set table time.
  push("time");
  push(tv);
  set_table(-3);

  // Set table context.
  push("context");
  push(cp);
  set_table(-3);

  // config.connection_up(event)
  try {
call(1, 0);
  } catch (std::exception& e) {
pop();
throw;
  }

  // Still got 'config' left on stack, it can go.
  pop();
}

void cybermon_lua::push(const ntp_hdr& hdr)
{
    create_table(0, 3);

    push("leap_indicator");
    push(hdr.m_leap_indicator);
    set_table(-3);
    
    push("version");
    push(hdr.m_version);
    set_table(-3);
    
    push("mode");
    push(hdr.m_mode);
    set_table(-3);
}

void cybermon_lua::push(const ntp_timestamp& ts)
{    
    create_table(0, 11);
    
    push("stratum");
    push(ts.m_stratum);
    set_table(-3);
    
    push("poll");
    push(ts.m_poll);
    set_table(-3);
    
    push("precision");
    push(ts.m_precision);
    set_table(-3);
    
    push("root_delay");
    push(ts.m_root_delay);
    set_table(-3);
    
    push("root_dispersion");
    push(ts.m_root_dispersion);
    set_table(-3);
     
    push("reference_id");
    push(ts.m_reference_id);
    set_table(-3);
    
    push("reference_timestamp");
    push(ts.m_reference_timestamp);
    set_table(-3);
    
    push("originate_timestamp");
    push(ts.m_originate_timestamp);
    set_table(-3);
    
    push("receive_timestamp");
    push(ts.m_receive_timestamp);
    set_table(-3);
    
    push("transmit_timestamp");
    push(ts.m_transmit_timestamp);
    set_table(-3);
    
    push("extension");
    push_bool(ts.m_has_extension);
    set_table(-3);
}

void cybermon_lua::push(const ntp_control& ctrl)
{
    create_table(0, 10);
    
    push("type");
    if(ctrl.m_is_response)
    {
        push("response");
    }
    else
    {
        push("request");
    }
    set_table(-3);
    
    push("error");
    push_bool(ctrl.m_is_error);
    set_table(-3);
    
    push("fragment");
    push_bool(ctrl.m_is_fragment);
    set_table(-3);
    
    push("opcode");
    push(ctrl.m_opcode);
    set_table(-3);
    
    push("sequence");
    push(ctrl.m_sequence);
    set_table(-3);
    
    push("status");
    push(ctrl.m_status);
    set_table(-3);
    
    push("association_id");
    push(ctrl.m_association_id);
    set_table(-3);
    
    push("offset");
    push(ctrl.m_offset);
    set_table(-3);
    
    push("data_length");
    push(ctrl.m_data_count);
    set_table(-3);
    
    push("authentication");
    push_bool(ctrl.m_has_authentication);
    set_table(-3);
}

void cybermon_lua::push(const ntp_private& priv)
{
    create_table(0, 4);

    push("auth");
    push_bool(priv.m_auth_flag);
    set_table(-3);
    
    push("sequence");
    push(priv.m_sequence);
    set_table(-3);
    
    push("implementation");
    push(priv.m_implementation);
    set_table(-3);
    
    push("request_code");
    push(priv.m_request_code);
    set_table(-3);
} 

void cybermon_lua::push(const dns_header& hdr)
{

    create_table(0, 8);
    
    push("id");
    push(hdr.id);
    set_table(-3);

    push("qr");
    push(hdr.qr);
    set_table(-3);

    push("opcode");
    push(hdr.opcode);
    set_table(-3);

    push("aa");
    push(hdr.aa);
    set_table(-3);

    push("tc");
    push(hdr.tc);
    set_table(-3);

    push("rd");
    push(hdr.rd);
    set_table(-3);

    push("ra");
    push(hdr.ra);
    set_table(-3);

    push("rcode");
    push(hdr.rcode);
    set_table(-3);

    push("qdcount");
    push(hdr.qdcount);
    set_table(-3);

    push("ancount");
    push(hdr.ancount);
    set_table(-3);

    push("nscount");
    push(hdr.nscount);
    set_table(-3);

    push("arcount");
    push(hdr.arcount);
    set_table(-3);

}

void cybermon_lua::push(const dns_query& qry)
{

    create_table(0, 3);

    push("name");
    push(qry.name);
    set_table(-3);

    push("type");
    push(qry.type);
    set_table(-3);

    push("class");
    push(qry.cls);
    set_table(-3);

}

void cybermon_lua::push(const dns_rr& rr)
{

    create_table(0, 7);

    push("name");
    push(rr.name);
    set_table(-3);

    push("type");
    push(rr.type);
    set_table(-3);

    push("class");
    push(rr.cls);
    set_table(-3);

    push("rdata");
    push(rr.rdata.begin(), rr.rdata.end());
    set_table(-3);

    push("ttl");
    push(rr.ttl);
    set_table(-3);

    if (rr.rdname != "") {
	push("rdname");
	push(rr.rdname);
	set_table(-3);
    }

    if (rr.rdaddress.addr.size() != 0) {

	if (rr.rdaddress.addr.size() == 4) {
	    // IPv4 address.
	    push("rdaddress");
	    push(rr.rdaddress.to_ip4_string());
	    set_table(-3);
	}

	if (rr.rdaddress.addr.size() == 16) {
	    // IPv6 address.
	    push("rdaddress");
	    push(rr.rdaddress.to_ip6_string());
	    set_table(-3);
	}

    }

}


void cybermon_lua::push(const std::list<dns_query>& lst)
{

    create_table(lst.size(), 0);

    int row = 1;
    for(std::list<dns_query>::const_iterator it = lst.begin();
	it != lst.end();
	it++) {
	
	push(row++);
	push(*it);
	set_table(-3);

    }

}

void cybermon_lua::push(const std::list<dns_rr>& lst)
{

    create_table(lst.size(), 0);

    int row = 1;
    for(std::list<dns_rr>::const_iterator it = lst.begin();
	it != lst.end();
	it++) {
	
	push(row++);
	push(*it);
	set_table(-3);

    }

}

void cybermon_lua::to_dns_query(int pos, dns_query& d)
{
    
    get_field(pos, "name");
    to_string(-1, d.name);
    pop();

    get_field(pos, "type");
    to_integer(-1, d.type);
    pop();

    get_field(pos, "class");
    to_integer(-1, d.cls);
    pop();

}

void cybermon_lua::to_dns_queries(int pos, std::list<dns_query>& lst)
{

    int len = raw_len(pos);

    lst.clear();


    for(int i = 1; i <= len; i++) {
	
	push(i);

	// Take into account the value I just pushed.
	get_table(pos - 1);
	
	dns_query q;
	to_dns_query(-1, q);

	pop();

	lst.push_back(q);

    }

}

void cybermon_lua::to_dns_rr(int pos, dns_rr& d)
{
    
    get_field(pos, "name");
    to_string(-1, d.name);
    pop();

    get_field(pos, "type");
    to_integer(-1, d.type);
    pop();

    get_field(pos, "class");
    to_integer(-1, d.cls);
    pop();

    get_field(pos, "ttl");
    to_integer(-1, d.ttl);
    pop();

    get_field(pos, "rdname");
    if (!is_nil(-1)) {
	to_string(-1, d.rdname);
    }
    pop();

    get_field(pos, "rdaddress");
    if (!is_nil(-1)) {
	std::string a;
	to_string(-1, a);
	d.rdaddress.from_ip_string(a);
    }
    pop();

    get_field(pos, "rdata");
    if (!is_nil(-1)) {
	std::string a;
	to_string(-1, a);
	d.rdata.clear();
	std::copy(a.begin(), a.end(), back_inserter(d.rdata));
    }
    pop();

}

void cybermon_lua::to_dns_rrs(int pos, std::list<dns_rr>& lst)
{

    int len = raw_len(pos);

    lst.clear();

    for(int i = 1; i <= len; i++) {
	
	push(i);

	// Take into account the value I just pushed.
	get_table(pos - 1);
	
	dns_rr r;
	to_dns_rr(-1, r);

	pop();

	lst.push_back(r);

    }

}

void cybermon_lua::to_dns_header(int pos, dns_header& hdr)
{
    
    get_field(pos, "id");
    to_integer(-1, hdr.id);
    pop();

    get_field(pos, "qr");
    to_integer(-1, hdr.qr);
    pop();

    get_field(pos, "opcode");
    to_integer(-1, hdr.opcode);
    pop();

    get_field(pos, "aa");
    to_integer(-1, hdr.aa);
    pop();

    get_field(pos, "tc");
    to_integer(-1, hdr.tc);
    pop();

    get_field(pos, "rd");
    to_integer(-1, hdr.rd);
    pop();

    get_field(pos, "ra");
    to_integer(-1, hdr.ra);
    pop();

    get_field(pos, "rcode");
    to_integer(-1, hdr.rcode);
    pop();

    get_field(pos, "qdcount");
    to_integer(-1, hdr.qdcount);
    pop();

    get_field(pos, "ancount");
    to_integer(-1, hdr.ancount);
    pop();

    get_field(pos, "nscount");
    to_integer(-1, hdr.nscount);
    pop();

    get_field(pos, "arcount");
    to_integer(-1, hdr.arcount);
    pop();

}

void cybermon_lua::push(context_ptr cp)
{

    void* ud = new_userdata(sizeof(context_userdata));
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    // Placement 'new' to initialise the thing.
    cd = new (cd) context_userdata;

    cd->ctxt = cp;
    cd->cml = this;

    get_meta_table("cybermon.context");
    set_meta_table(-2);

}

void cybermon_lua::push(const timeval& time)
{

    char t[256];

    // Convert time (seconds) to struct tm
    struct tm* tmv = gmtime(&time.tv_sec);
    if (tmv == 0) {
	push("not-a-time");
	return;
    }

    // Format time in seconds
    if (strftime(t, 256, "%Y-%m-%dT%H:%M:%S", tmv) == 0) {
	push("not-a-time");
	return;
    }

    // Add milliseconds.
    sprintf(t + strlen(t), ".%03dZ", int(time.tv_usec / 1000));

    // Push time string to stack.
    push(t);

}

int cybermon_lua::context_get_parent(lua_State *lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    context_ptr par = cd->ctxt->get_parent();

    cd->cml->pop();
    
    if (par)
	cd->cml->push(par);
    else
	cd->cml->push();

    return 1;

}

int cybermon_lua::context_get_reverse(lua_State *lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    context_ptr par = cd->ctxt->get_reverse();

    cd->cml->pop();

    if (par)
	cd->cml->push(par);
    else
	cd->cml->push();

    return 1;

}

int cybermon_lua::context_get_id(lua_State *lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    context_id id = cd->ctxt->get_id();

    cd->cml->pop(1);
    cd->cml->push(id);

    return 1;

}

int cybermon_lua::context_gc(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    cd->ctxt.reset();

    cd->cml->pop();

    return 1;
}

int cybermon_lua::context_get_src_addr(lua_State *lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string cls, addr;
    cd->ctxt->get_src(cls, addr);

    cd->cml->pop();
    cd->cml->push(cls);
    cd->cml->push(addr);

    return 2;

}

int cybermon_lua::context_get_dest_addr(lua_State *lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string cls, addr;
    cd->ctxt->get_dest(cls, addr);

    cd->cml->pop();
    cd->cml->push(cls);
    cd->cml->push(addr);

    return 2;

}

int cybermon_lua::context_describe_src(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::ostringstream buf;

    cybermon::engine::describe_src(cd->ctxt, buf);

    cd->cml->pop(1);

    cd->cml->push(buf.str());

    return 1;
}

int cybermon_lua::context_describe_dest(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::ostringstream buf;

    cybermon::engine::describe_dest(cd->ctxt, buf);

    cd->cml->pop(1);

    cd->cml->push(buf.str());

    return 1;
}

int cybermon_lua::context_get_type(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string type = cd->ctxt->get_type();

    cd->cml->pop(1);

    cd->cml->push(type);

    return 1;

}

int cybermon_lua::context_get_creation_time(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    struct timeval* creation = &(cd->ctxt->creation);

    double d = creation->tv_sec + (creation->tv_usec / 1000000.0);

    cd->cml->pop(1);
    cd->cml->push(d);

    return 1;

}

int cybermon_lua::context_get_direction(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    direction dir = cd->ctxt->addr.direc;

    cd->cml->pop(1);

    if (dir == FROM_TARGET)
        cd->cml->push("FROM_DEVICE");
    else if (dir == TO_TARGET)
        cd->cml->push("TO_DEVICE");
    else
        cd->cml->push("NOT_KNOWN");

    return 1;

}

int cybermon_lua::context_get_liid(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string liid;
    address trigger_address;
    engine::get_root_info(cd->ctxt, liid, trigger_address);

    cd->cml->pop(1);
    cd->cml->push(liid);

    return 1;

}

int cybermon_lua::context_get_trigger_info(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string liid;
    address trigger_address;
    engine::get_root_info(cd->ctxt, liid, trigger_address);

    cd->cml->pop(1);

    if (trigger_address.addr.size() == 0)
	cd->cml->push();
    else
	try {
	    cd->cml->push(trigger_address.to_ip_string());
	} catch (...) {
	    cd->cml->push();
	}

    return 1;

}

int cybermon_lua::context_get_network_info(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string network;
    address src, dest;
    engine::get_network_info(cd->ctxt, network, src, dest);

    cd->cml->pop(1);
    cd->cml->push(network);
    cd->cml->push(src.to_ip_string());
    cd->cml->push(dest.to_ip_string());

    return 3;

}


int cybermon_lua::context_forge_dns_response(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    // FIXME: Fails for some reason?!  I don't understand the API prob'ly.
/*
    luaL_checktype(lua, 2, LUA_TTABLE); // Header
    luaL_checktype(lua, 3, LUA_TTABLE); // Queries
    luaL_checktype(lua, 4, LUA_TTABLE); // Answers
    luaL_checktype(lua, 5, LUA_TTABLE); // Authorities
    luaL_checktype(lua, 6, LUA_TTABLE); // Additional
*/

    dns_header hdr;
    cd->cml->to_dns_header(-5, hdr);

    std::list<dns_query> queries;
    cd->cml->to_dns_queries(-4, queries);

    std::list<dns_rr> answers;
    cd->cml->to_dns_rrs(-3, answers);

    std::list<dns_rr> authorities;
    cd->cml->to_dns_rrs(-2, authorities);

    std::list<dns_rr> additional;
    cd->cml->to_dns_rrs(-1, additional);

    forgery::forge_dns_response(cd->ctxt, hdr, queries, answers, 
				authorities, additional);

    // Pop all arguments.
    cd->cml->pop(6);

    return 0;

}

int cybermon_lua::context_forge_tcp_reset(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    forgery::forge_tcp_reset(cd->ctxt);

    cd->cml->pop(1);

    return 0;

}

int cybermon_lua::context_forge_tcp_data(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    pdu data;
    cd->cml->to_string(-1, data);

    forgery::forge_tcp_data(cd->ctxt, data.begin(), data.end());

    cd->cml->pop(2);

    return 0;

}

// Registers into a metatable.
void lua_state::register_table(const std::map<std::string,lua_CFunction>& fns) {
	    
#ifdef HAVE_LUAL_SETFUNCS
    // LUA 5.2 and on
    luaL_Reg cfns[fns.size() + 1];
#else
    // LUA 5.1
    luaL_reg cfns[fns.size() + 1];
#endif

    int pos = 0;
    for(std::map<std::string,lua_CFunction>::const_iterator it = 
	    fns.begin();
	it != fns.end();
	it++) {
	cfns[pos].name = it->first.c_str();
	cfns[pos].func = it->second;
	pos++;
    }
	    
    cfns[pos].name = 0;
    cfns[pos].func = 0;
	   
#ifdef HAVE_LUAL_SETFUNCS
    // LUA 5.2 and on
    luaL_setfuncs(lua, cfns, 0);
    // FIXME: Is this right?
    set_meta_table(-2);
#else
    // LUA 5.1
    luaL_register(lua, 0, cfns);
#endif
	    
}

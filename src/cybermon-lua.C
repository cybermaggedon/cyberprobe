
#include <sstream>

#include <cybermon/cybermon-lua.h>
#include <cybermon/forgery.h>

using namespace cybermon;

// Call the config.trigger_up function as trigger_up(liid, addr)
void cybermon_lua::trigger_up(const std::string& liid, const tcpip::address& a)
{
 
    // Get information stored about the attacker.
    std::string ta;
    a.to_string(ta);

    // Get config.trigger_up
    get_global("config");
    get_field(-1, "trigger_up");
    
    // Put liid on stack
    push(liid);
    push(ta);
	
    // config.trigger_up(liid, addr)
    try {
	call(2, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}

// Call the config.trigger_down function as trigger_down(liid, addr)
void cybermon_lua::trigger_down(const std::string& liid)
{

    // Get config.trigger_down
    get_global("config");
    get_field(-1, "trigger_down");
    
    // Put liid on stack
    push(liid);
	
    // config.trigger_down(liid)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }

    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a userdata pointer,
// allowing calling back into the C++ code.
void cybermon_lua::connection_up(engine& an, 
				 context_ptr f)
{

    // Get config.connection_up
    get_global("config");
    get_field(-1, "connection_up");
    
    // Put context on the stack
    push(f);
    
    // config.connection_up(context)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::connection_down(engine& an, 
				   const context_ptr f)
{
    
    // Get config.connection_down
    get_global("config");
    get_field(-1, "connection_down");
    
    // Put context on the stack
    push(f);
    
    // config.connection_down(context)
    try {
	call(1, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::unrecognised_stream(engine& an, 
				       const context_ptr f, 
				       pdu_iter s, 
				       pdu_iter e)
{
    
    // Get config.unrecognised_stream
    get_global("config");
    get_field(-1, "unrecognised_stream");
    
    // Put context on the stack
    push(f);

    // Put data on stack.
    push(s, e);
    
    // config.unrecognised_stream(context, data)
    try {
	call(2, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::unrecognised_datagram(engine& an, 
					 const context_ptr f, 
					 pdu_iter s, 
					 pdu_iter e)
{
    
    // Get config.unrecognised_datagram
    get_global("config");
    get_field(-1, "unrecognised_datagram");
    
    // Put context on stack.
    push(f);

    // Put data on stack.
    push(s, e);
    
    // config.unrecognised_datagram(context, data)
    try {
	call(2, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}


void cybermon_lua::icmp(engine& an, 
			const context_ptr f, 
			pdu_iter s, 
			pdu_iter e)
{

    // Get config.icmp
    get_global("config");
    get_field(-1, "icmp");
    
    // Put context on the stack
    push(f);

    // Put data on stack.
    push(s, e);
    
    // config.icmp(context, data)
    try {
	call(2, 0);
    } catch (std::exception& e) {
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
				pdu_iter e)
{

    // Get config.http_request
    get_global("config");
    get_field(-1, "http_request");
    
    // Put context on the stack
    push(f);

    // Push method
    push(method);

    // Push URL
    push(url);

    // Build header table on stack.
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

    // Put data on stack.
    push(s, e);

    // config.http_request(context, method, url, header, body)
    try {
	call(5, 0);
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
				 pdu_iter e)
{

    // Get config.http_response
    get_global("config");
    get_field(-1, "http_response");
    
    // Put context on the stack
    push(f);

    // Push code
    push(code);

    // Push status
    push(status);

    // Build header table on stack.
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

    // Push fully normalised URL if known.
    push(url);

    // Put data on stack.
    push(s, e);

    // config.http_response(context, code, status, header, url, body)
    try {
	call(6, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::smtp_command(engine& an, const context_ptr f,
				const std::string& command)
{

    // Get config.smtp_command
    get_global("config");
    get_field(-1, "smtp_command");
    
    // Put context on the stack
    push(f);

    // Push method
    push(command);

    // config.smtp_command(context, command)
    try {
	call(2, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::smtp_response(engine& an, const context_ptr f,
				 int status,
				 const std::list<std::string>& text)
{

    // Get config.smtp_response
    get_global("config");
    get_field(-1, "smtp_response");
    
    // Put context on the stack
    push(f);

    // Push method
    push(status);

    // Build texts table on stack.
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

    // config.smtp_response(context, status, texts)
    try {
	call(3, 0);
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
			     pdu_iter s, pdu_iter e)
{

    // Get config.http_request
    get_global("config");
    get_field(-1, "smtp_data");
    
    // Put context on the stack
    push(f);

    // Push from.
    push(from);

    // Build to table on stack.
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

    // Push data.
    push(s, e);

    // config.smtp_data(context, from, to, data)
    try {
	call(4, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::ftp_command(engine& an, const context_ptr f,
			       const std::string& command)
{

    // Get config.http_request
    get_global("config");
    get_field(-1, "ftp_command");
    
    // Put context on the stack
    push(f);

    // Push method
    push(command);

    // config.ftp_command(context, command)
    try {
	call(2, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

void cybermon_lua::ftp_response(engine& an, const context_ptr f,
				int status,
				const std::list<std::string>& text)
{

    // Get config.ftp_request
    get_global("config");
    get_field(-1, "ftp_response");
    
    // Put context on the stack
    push(f);

    // Push method
    push(status);

    // Build texts table on stack.
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

    // config.ftp_response(context, status, texts)
    try {
	call(3, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

}

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
    afns["get_event_time"] = &context_get_event_time;

    register_table(afns);

    // Pop meta-table
    pop();

}

void cybermon_lua::dns_message(engine& an, const context_ptr f,
			       const dns_header& hdr, 
			       const std::list<dns_query> queries,
			       const std::list<dns_rr> answers,
			       const std::list<dns_rr> authorities,
			       const std::list<dns_rr> additional)
{

    // Get config.dns_message
    get_global("config");
    get_field(-1, "dns_message");
    
    // Put context on the stack
    push(f);

    push(hdr);
    push(queries);
    push(answers);
    push(authorities);
    push(additional);

    // config.dns_message(context, hdr, queries, answers, authorities,
    // additional)
    try {
	call(6, 0);
    } catch (std::exception& e) {
	pop();
	throw;
    }
    
    // Still got 'config' left on stack, it can go.
    pop();

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

int cybermon_lua::context_get_event_time(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    struct timeval event;
    gettimeofday(&event, 0);

    double d = event.tv_sec + (event.tv_usec / 1000000.0);

    cd->cml->pop(1);
    cd->cml->push(d);

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

    address src, dest;
    engine::get_network_info(cd->ctxt, src, dest);

    cd->cml->pop(1);
    cd->cml->push(src.to_ip_string());
    cd->cml->push(dest.to_ip_string());

    return 2;

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

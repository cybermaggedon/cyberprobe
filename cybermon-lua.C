
#include <sstream>
#include <cybermon-lua.h>

using namespace cybermon;

int cybermon_lua::describe_src(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    h->cml->describe_src(h);
    return 1;
}

int cybermon_lua::describe_dest(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    h->cml->describe_dest(h);
    return 1;
}

int cybermon_lua::get_liid(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    h->cml->get_liid(h);
    return 1;
}

int cybermon_lua::get_context_id(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    h->cml->get_context_id(h);
    return 1;
}

int cybermon_lua::get_network_info(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    return h->cml->get_network_info(h);
}

int cybermon_lua::get_trigger_info(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    return h->cml->get_trigger_info(h);
}

int cybermon_lua::forge_dns_response(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -6);
    context_userdata* h = reinterpret_cast<context_userdata*>(ud);
    return h->cml->forge_dns_response(h);
}

void cybermon_lua::describe_src(context_userdata* h)
{
    std::ostringstream buf;
    engine::describe_src(h->ctxt, buf);

    // Pop user-data argument
    pop(1);

    // Put address string on stack.
    push(buf.str());

}

void cybermon_lua::describe_dest(context_userdata* h)
{

    std::ostringstream buf;
    engine::describe_dest(h->ctxt, buf);

    // Pop user-data argument
    pop(1);

    // Put address string on stack.
    push(buf.str());

}

int cybermon_lua::get_liid(context_userdata* h)
{

    // Pop user-data argument
    pop(1);

    // Get LIID
    std::string liid;
    address trigger_address;
    engine::get_root_info(h->ctxt, liid, trigger_address);

    // Push LIID on stack.
    push(liid);

    return 1;

}

void cybermon_lua::get_context_id(context_userdata* h)
{

    // Pop user-data argument
    pop(1);

    // Put Context ID on stack
    push(h->ctxt->get_id());

}

int cybermon_lua::get_network_info(context_userdata* h)
{

    // Pop user-data argument
    pop(1);

    address src, dest;
    engine::get_network_info(h->ctxt, src, dest);

    push(src.to_ip_string());
    push(dest.to_ip_string());

    return 2;

}

int cybermon_lua::get_trigger_info(context_userdata* h)
{

    // Pop user-data argument
    pop(1);

    // Get trigger address
    std::string liid;
    address trigger_address;
    engine::get_root_info(h->ctxt, liid, trigger_address);

    push(trigger_address.to_ip_string());

    return 1;

}

int cybermon_lua::forge_dns_response(context_userdata* h)
{

    std::cerr << "Table has " << lua_objlen(lua, -4) << " queries." << std::endl;
    std::cerr << "Table has " << lua_objlen(lua, -3) << " answers." << std::endl;

    // Pop all arguments.
    pop(6);

    std::cerr << "forge_dns_response not implemented." << std::endl;

    return 0;

}

// Call the config.trigger_up function as trigger_up(liid, addr)
void cybermon_lua::trigger_up(const std::string& liid, const tcpip::address& a)
{
 
    // Get information stored about the attacker.
    std::string ta;
    a.to_string(ta);

    // Get observer.trigger_up
    lua_getfield(lua, LUA_GLOBALSINDEX, "config");
    lua_getfield(lua, -1, "trigger_up");
    
    // Put liid on stack
    lua_pushstring(lua, liid.c_str());
    lua_pushstring(lua, ta.c_str());
	
    // observer.trigger_up(liid, addr)
    lua_call(lua, 2, 0);

    // Still got 'observer' left on stack, it can go.
    lua_pop(lua, 1); 

}

// Call the config.trigger_down function as trigger_down(liid, addr)
void cybermon_lua::trigger_down(const std::string& liid)
{

    // Get observer.trigger_down
    lua_getfield(lua, LUA_GLOBALSINDEX, "config");
    lua_getfield(lua, -1, "trigger_down");
    
    // Put liid on stack
    lua_pushstring(lua, liid.c_str());
	
    // observer.trigger_down(liid)
    lua_call(lua, 1, 0);

    // Still got 'observer' left on stack, it can go.
    lua_pop(lua, 1); 

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::connection_up(engine& an, 
				 const context_ptr f)
{

    context_userdata h;

    h.ctxt = f;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "connection_up");
    
    // Put hideous on the stack
    push(h);
    
    // observer.connection_up(context)
    call(1, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::connection_down(engine& an, 
				 const context_ptr f)
{

    context_userdata h;

    h.ctxt = f;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "connection_down");
    
    // Put hideous on the stack
    push(h);
    
    // observer.connection_down(context)
    call(1, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

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

    context_userdata h;

    h.ctxt = f;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "connection_data");
    
    // Put hideous on the stack
    push(h);

    // Put data on stack.
    push(s, e);
    
    // observer.data(context, data)
    call(2, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

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

    context_userdata h;
    h.ctxt = f;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "unrecognised_datagram");
    
    // Put hideous on the stack
    push(h);

    // Put data on stack.
    push(s, e);
    
    // observer.data(context, data)
    call(2, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}


void cybermon_lua::icmp(engine& an, 
			const context_ptr f, 
			pdu_iter s, 
			pdu_iter e)
{

    context_userdata h;
    h.ctxt = f;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "icmp");
    
    // Put hideous on the stack
    push(h);

    // Put data on stack.
    push(s, e);
    
    // observer.data(context, data)
    call(2, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

void cybermon_lua::http_request(engine& an, const context_ptr f,
				const std::string& method,
				const std::string& url,
				const http_header& hdr,
				pdu_iter s,
				pdu_iter e)
{

    context_userdata h;
    h.ctxt = f;
    h.cml = this;
    
    // Get observer.http_request
    get_global("config");
    get_field(-1, "http_request");
    
    // Put hideous on the stack
    push(h);

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

    // observer.data(context, data)
    call(5, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

void cybermon_lua::http_response(engine& an, const context_ptr f,
				 unsigned int code,
				 const std::string& status,
				 const http_header& hdr,
				 const std::string& url,
				 pdu_iter s,
				 pdu_iter e)
{

    context_userdata h;
    h.ctxt = f;
    h.cml = this;
    
    // Get observer.http_request
    get_global("config");
    get_field(-1, "http_response");
    
    // Put hideous on the stack
    push(h);

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

    // observer.data(context, data)
    call(6, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

cybermon_lua::cybermon_lua(const std::string& cfg)
{
	
    // C functions go in a map.
    std::map<std::string,lua_CFunction> fns;
    fns["describe_src"] = &describe_src;
    fns["describe_dest"] = &describe_dest;
    fns["get_liid"] = &get_liid;
    fns["get_context_id"] = &get_context_id;
    fns["get_network_info"] = &get_network_info;
    fns["get_trigger_info"] = &get_trigger_info;
    fns["forge_dns_response"] = &forge_dns_response;

    // These are registered with lua as the 'cybermon' module.
    register_module("cybermon", fns);

    // Load the configuration file.
    load_module(cfg);

    // Transfer result from module to global variable 'config'.
    set_global("config");

}

void cybermon_lua::dns_message(engine& an, const context_ptr f,
			       const dns_header& hdr, 
			       const std::list<dns_query> queries,
			       const std::list<dns_rr> answers,
			       const std::list<dns_rr> authorities,
			       const std::list<dns_rr> additional)
{

    context_userdata h;
    h.ctxt = f;
    h.cml = this;
    
    // Get observer.http_request
    get_global("config");
    get_field(-1, "dns_message");
    
    // Put hideous on the stack
    push(h);

    push(hdr);
    push(queries);
    push(answers);
    push(authorities);
    push(additional);

    // observer.data(context, data)
    call(6, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

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

    if (rr.addr.addr.size() != 0) {

	if (rr.addr.addr.size() == 4) {
	    // IPv4 address.
	    push("rdaddress");
	    push(rr.addr.to_ip4_string());
	    set_table(-3);
	}

	if (rr.addr.addr.size() == 16) {
	    // IPv6 address.
	    push("rdaddress");
	    push(rr.addr.to_ip6_string());
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



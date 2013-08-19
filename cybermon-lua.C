
#include <sstream>
#include <cybermon-lua.h>

using namespace analyser;

int cybermon_lua::describe_src(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    cybermon_context* h = reinterpret_cast<cybermon_context*>(ud);
    h->cml->describe_src(h);
    return 1;
}

int cybermon_lua::describe_dest(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    cybermon_context* h = reinterpret_cast<cybermon_context*>(ud);
    h->cml->describe_dest(h);
    return 1;
}

int cybermon_lua::get_liid(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    cybermon_context* h = reinterpret_cast<cybermon_context*>(ud);
    h->cml->get_liid(h);
    return 1;
}

int cybermon_lua::get_context_id(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    cybermon_context* h = reinterpret_cast<cybermon_context*>(ud);
    h->cml->get_context_id(h);
    return 1;
}

int cybermon_lua::get_network_info(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    cybermon_context* h = reinterpret_cast<cybermon_context*>(ud);
    return h->cml->get_network_info(h);
}

int cybermon_lua::get_trigger_info(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    cybermon_context* h = reinterpret_cast<cybermon_context*>(ud);
    return h->cml->get_trigger_info(h);
}

void cybermon_lua::describe_src(cybermon_context* h)
{
    std::ostringstream buf;
    analyser::engine::describe_src(h->ctxt, buf);

    // Pop user-data argument
    pop(1);

    // Put address string on stack.
    push(buf.str().c_str());

}

void cybermon_lua::describe_dest(cybermon_context* h)
{

    std::ostringstream buf;
    analyser::engine::describe_dest(h->ctxt, buf);

    // Pop user-data argument
    lua_pop(lua, 1);

    // Put address string on stack.
    lua_pushstring(lua, buf.str().c_str());

}

void cybermon_lua::get_liid(cybermon_context* h)
{

    // Pop user-data argument
    pop(1);

    // Put LIID on stack
    push(h->liid.c_str());

}

void cybermon_lua::get_context_id(cybermon_context* h)
{

    // Pop user-data argument
    pop(1);

    // Put Context ID on stack
    push(h->ctxt->get_id());

}

int cybermon_lua::get_network_info(cybermon_context* h)
{

    // Pop user-data argument
    pop(1);

    analyser::address src, dest;
    analyser::engine::get_network_info(h->ctxt, src, dest);

    tcpip::ip4_address x;
    std::string a1, a2;

    x.addr.assign(src.addr.begin(), src.addr.end());
    x.to_string(a1);

    x.addr.assign(dest.addr.begin(), dest.addr.end());
    x.to_string(a2);

    // Put address strings on stack
    push(a1);
    push(a2);

    return 2;

}

int cybermon_lua::get_trigger_info(cybermon_context* h)
{

    // Pop user-data argument
    pop(1);

    tcpip::ip4_address x;
    std::string a1;

    x.addr.assign(h->trigger.addr.begin(), h->trigger.addr.end());
    x.to_string(a1);

    // Put address string on stack
    push(a1);

    return 1;

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
void cybermon_lua::connection_up(analyser::engine& an, 
				 const analyser::context_ptr f)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    an.get_root_info(f, liid, trigger_address);

    cybermon_context h;

    h.an = &an;
    h.ctxt = f;
    h.liid = liid;
    h.trigger = trigger_address;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "connection_up");
    
    // Put hideous on the stack
    push_cybermon_context(h);
    
    // observer.connection_up(context)
    call(1, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::connection_down(analyser::engine& an, 
				 const analyser::context_ptr f)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    an.get_root_info(f, liid, trigger_address);

    cybermon_context h;

    h.an = &an;
    h.ctxt = f;
    h.liid = liid;
    h.trigger = trigger_address;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "connection_down");
    
    // Put hideous on the stack
    push_cybermon_context(h);
    
    // observer.connection_down(context)
    call(1, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::connection_data(analyser::engine& an, 
				   const analyser::context_ptr f, 
				   analyser::pdu_iter s, 
				   analyser::pdu_iter e)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    an.get_root_info(f, liid, trigger_address);

    cybermon_context h;

    h.an = &an;
    h.ctxt = f;
    h.s = s;
    h.e = e;
    h.liid = liid;
    h.trigger = trigger_address;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "connection_data");
    
    // Put hideous on the stack
    push_cybermon_context(h);

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
void cybermon_lua::datagram(analyser::engine& an, 
			    const analyser::context_ptr f, 
			    analyser::pdu_iter s, 
			    analyser::pdu_iter e)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    an.get_root_info(f, liid, trigger_address);

    cybermon_context h;
    h.an = &an;
    h.ctxt = f;
    h.s = s;
    h.e = e;
    h.liid = liid;
    h.trigger = trigger_address;
    h.cml = this;
    
    // Get observer.data
    get_global("config");
    get_field(-1, "datagram");
    
    // Put hideous on the stack
    push_cybermon_context(h);

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
				const std::map<std::string,std::string>& hdr,
				pdu_iter s,
				pdu_iter e)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    an.get_root_info(f, liid, trigger_address);

    cybermon_context h;
    h.an = &an;
    h.ctxt = f;
    h.s = s;
    h.e = e;
    h.liid = liid;
    h.trigger = trigger_address;
    h.cml = this;
    
    // Get observer.http_request
    get_global("config");
    get_field(-1, "http_request");
    
    // Put hideous on the stack
    push_cybermon_context(h);

    // Push method
    push(method);

    // Push URL
    push(url);

    // Build header table on stack.
    create_table(0, hdr.size());

    // Loop through header
    for(std::map<std::string,std::string>::const_iterator it = hdr.begin();
	it != hdr.end();
	it++) {

	// Set table row.
	push(it->first);
	push(it->second);
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
				 const std::map<std::string,std::string>& hdr,
				 pdu_iter s,
				 pdu_iter e)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    an.get_root_info(f, liid, trigger_address);

    cybermon_context h;
    h.an = &an;
    h.ctxt = f;
    h.s = s;
    h.e = e;
    h.liid = liid;
    h.trigger = trigger_address;
    h.cml = this;
    
    // Get observer.http_request
    get_global("config");
    get_field(-1, "http_response");
    
    // Put hideous on the stack
    push_cybermon_context(h);

    // Push method
    push(code);

    // Push URL
    push(status);

    // Build header table on stack.
    create_table(0, hdr.size());

    // Loop through header
    for(std::map<std::string,std::string>::const_iterator it = hdr.begin();
	it != hdr.end();
	it++) {

	// Set table row.
	push(it->first);
	push(it->second);
	set_table(-3);

    }

    // Put data on stack.
    push(s, e);

    // observer.data(context, data)
    call(5, 0);
    
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

    // These are registered with lua as the 'cybermon' module.
    register_module("cybermon", fns);

    // Load the configuration file.
    load_module(cfg);

    // Transfer result from module to global variable 'config'.
    set_global("config");

}


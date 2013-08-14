
#include <sstream>
#include <cybermon-lua.h>

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

// Call the config.trigger function as trigger(liid, addr)
void cybermon_lua::trigger(const std::string& liid, const tcpip::address& a)
{
 
    // Get information stored about the attacker.
    std::string ta;
    a.to_string(ta);

    // Get observer.trigger
    lua_getfield(lua, LUA_GLOBALSINDEX, "config");
    lua_getfield(lua, -1, "trigger");
    
    // Put liid on stack
    lua_pushstring(lua, liid.c_str());
    lua_pushstring(lua, ta.c_str());
	
    // observer.data(context, data)
    lua_call(lua, 2, 0);

    // Still got 'observer' left on stack, it can go.
    lua_pop(lua, 1); 

}

// Calls the config.data function as data(context, data).
// The 'context' variable passed to LUA is a light userdata pointer,
// allowing calling back into the C++ code.  The value is only valid
// in LUA space for the duration of this call.
void cybermon_lua::data(analyser::engine& an, const analyser::context_ptr f, 
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
    get_field(-1, "data");
    
    // Put hideous on the stack
    push_cybermon_context(h);

    // Put data on stack.
    push(s, e);
    
    // observer.data(context, data)
    call(2, 0);
    
    // Still got 'observer' left on stack, it can go.
    pop(1);

}

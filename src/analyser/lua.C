
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sstream>

#include <cyberprobe/analyser/lua.h>
#include <cyberprobe/protocol/forgery.h>
#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/event/event.h>

using namespace cyberprobe;
using namespace cyberprobe::analyser;
using namespace cyberprobe::protocol;

lua::lua(const std::string& cfg)
{

    // Add configuration file's directory to package.path.
    add_parent_directory_path(cfg);

    // Load the configuration file.
    load_module(cfg);

    // Transfer result from module to global variable 'config'.
    set_global("config");

    // -- cybermon.event meta table
    
    // Put new meta-table on the stack.
    new_meta_table("cybermon.event");

    push("__index");
    push_value(-2);       /* pushes the metatable */
    set_table(-3);  /* metatable.__index = metatable */

    std::map<std::string,lua_CFunction> afns;
    afns["__gc"] = &event_gc;
    afns["__index"] = &event_index;

    register_table(afns);

    // Pop meta-table
    pop();

    // -- cybermon.context meta table

    // Put new meta-table on the stack.
    new_meta_table("cybermon.context");

    push("__index");
    push_value(-2);       // pushes the metatable
    set_table(-3);        // metatable.__index = metatable

    std::map<std::string,lua_CFunction> cfns;
    cfns["__gc"] = &context_gc;
    cfns["get_type"] = &context_get_type;
    cfns["get_parent"] = &context_get_parent;
    cfns["get_src_addr"] = &context_get_src_addr;
    cfns["get_dest_addr"] = &context_get_dest_addr;
    cfns["get_reverse"] = &context_get_reverse;
    cfns["get_id"] = &context_get_id;
    cfns["describe_src"] = &context_describe_src;
    cfns["describe_dest"] = &context_describe_dest;
    cfns["get_context_id"] = &context_get_id;
    cfns["get_network_info"] = &context_get_network_info;
    cfns["get_trigger_info"] = &context_get_trigger_info;
    cfns["forge_dns_response"] = &context_forge_dns_response;
    cfns["forge_tcp_reset"] = &context_forge_tcp_reset;
    cfns["forge_tcp_data"] = &context_forge_tcp_data;
    cfns["get_creation_time"] = &context_get_creation_time;
    cfns["get_direction"] = &context_get_direction;
    register_table(cfns);

    // Pop meta-table
    pop();

#ifdef WITH_GRPC

    // -- cybermon.grpc meta table

    // Put new meta-table on the stack.
    new_meta_table("cybermon.grpc.manager");

    push("__index");
    push_value(-2);       // pushes the metatable
    set_table(-3);        // metatable.__index = metatable

    std::map<std::string,lua_CFunction> mfns;
    mfns["__gc"] = &grpc_gc;
    mfns["observe"] = &grpc_observe;
    register_table(mfns);

    // Pop meta-table
    pop();

    // -- gRPC initialisation
    auto grpc = grpc_manager::create();
    push(grpc);
    set_global("grpc");

#endif

}

#ifdef WITH_GRPC

void lua::push(std::shared_ptr<grpc_manager> grpc)
{

    void* ud = new_userdata(sizeof(grpc_userdata));
    grpc_userdata* gd = reinterpret_cast<grpc_userdata*>(ud);

    // Placement 'new' to initialise the thing.
    gd = new (gd) grpc_userdata;
    gd->grpc = grpc;
    gd->cml = this;

    get_meta_table("cybermon.grpc.manager");
    set_meta_table(-2);

}

#endif

int lua::event_index(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.event");
    luaL_argcheck(lua, ud != NULL, 1, "`event' expected");
    event_userdata* ed = reinterpret_cast<event_userdata*>(ud);

    std::string key;
    ed->cml->to_string(2, key);

    ed->cml->pop(2);

    return ed->event->get_lua_value(*(ed->cml), key);

}

int lua::event_gc(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    event_userdata* ed = reinterpret_cast<event_userdata*>(ud);

    // FIXME: No idea why this is here.
    ed->event.reset();

    ed->cml->pop();

    return 0;
}

int lua::context_gc(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    // FIXME: No idea why this is here.
    cd->ctxt.reset();

    cd->cml->pop();

    return 0;
}

#ifdef WITH_GRPC
int lua::grpc_gc(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -1);
    grpc_userdata* gd = reinterpret_cast<grpc_userdata*>(ud);

    gd->cml->pop();

    gd->grpc->close();

    return 0;
}

int lua::grpc_observe(lua_State* lua)
{
    void* ud = lua_touserdata(lua, -3);
    grpc_userdata* gd = reinterpret_cast<grpc_userdata*>(ud);

    ud = lua_touserdata(lua, -2);
    event_userdata* ed = reinterpret_cast<event_userdata*>(ud);

    std::string svc;
    gd->cml->to_string(-1, svc);

    gd->cml->pop(3);

    gd->grpc->observe(ed->event, svc);

    return 0;
}
#endif

void lua::event(engine& an, std::shared_ptr<event::event> ev)
{

    // Get config.event
    get_global("config");
    get_field(-1, "event");

    // Push event on stack
    push(ev);
    
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

void lua::push(const ntp_hdr& hdr)
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

void lua::push(const ntp_timestamp& ts)
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

void lua::push(const ntp_control& ctrl)
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

void lua::push(const ntp_private& priv)
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

void lua::push(const dns_header& hdr)
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

void lua::push(const dns_query& qry)
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

void lua::push(const dns_rr& rr)
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

void lua::push(const std::list<dns_query>& lst)
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

void lua::push(const std::list<dns_rr>& lst)
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

void lua::to_dns_query(int pos, dns_query& d)
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

void lua::to_dns_queries(int pos, std::list<dns_query>& lst)
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

void lua::to_dns_rr(int pos, dns_rr& d)
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

void lua::to_dns_rrs(int pos, std::list<dns_rr>& lst)
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

void lua::to_dns_header(int pos, dns_header& hdr)
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

void lua::push(context_ptr cp)
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

void lua::push(std::shared_ptr<event::event> ev)
{

    void* ud = new_userdata(sizeof(event_userdata));
    event_userdata* ed = reinterpret_cast<event_userdata*>(ud);

    // Placement 'new' to initialise the thing.
    ed = new (ed) event_userdata;

    ed->event = ev;
    ed->cml = this;

    get_meta_table("cybermon.event");
    set_meta_table(-2);

}

void lua::push(const timeval& time)
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

int lua::context_get_parent(lua_State *lua)
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

int lua::context_get_reverse(lua_State *lua)
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

int lua::context_get_id(lua_State *lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    context_id id = cd->ctxt->get_id();

    cd->cml->pop(1);
    cd->cml->push(id);

    return 1;

}

int lua::context_get_src_addr(lua_State *lua)
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

int lua::context_get_dest_addr(lua_State *lua)
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

int lua::context_describe_src(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::ostringstream buf;

    engine::describe_src(cd->ctxt, buf);

    cd->cml->pop(1);

    cd->cml->push(buf.str());

    return 1;
}

int lua::context_describe_dest(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::ostringstream buf;

    engine::describe_dest(cd->ctxt, buf);

    cd->cml->pop(1);

    cd->cml->push(buf.str());

    return 1;
}

int lua::context_get_type(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string type = cd->ctxt->get_type();

    cd->cml->pop(1);

    cd->cml->push(type);

    return 1;

}

int lua::context_get_creation_time(lua_State* lua)
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

int lua::context_get_direction(lua_State* lua)
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

int lua::context_get_trigger_info(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    std::string device;
    address trigger_address;
    engine::get_root_info(cd->ctxt, device, trigger_address);

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

int lua::context_get_network_info(lua_State* lua)
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


int lua::context_forge_dns_response(lua_State* lua)
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

int lua::context_forge_tcp_reset(lua_State* lua)
{

    void* ud = luaL_checkudata(lua, 1, "cybermon.context");
    luaL_argcheck(lua, ud != NULL, 1, "`context' expected");
    context_userdata* cd = reinterpret_cast<context_userdata*>(ud);

    forgery::forge_tcp_reset(cd->ctxt);

    cd->cml->pop(1);

    return 0;

}

int lua::context_forge_tcp_data(lua_State* lua)
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
#else
    // LUA 5.1
    luaL_register(lua, 0, cfns);
#endif
	    
}


luadir = ${sysconfdir}/@PACKAGE@
lua_DATA = monitor.lua forge-dns.lua quiet.lua forge-reset.lua \
	zeromq.lua redis.lua json.lua amqp-topic.lua protobuf.lua \
	grpc.lua pulsar.lua

sysconf_DATA = cyberprobe.cfg

utildir = ${sysconfdir}/@PACKAGE@/util
util_DATA = util/addresses.lua util/json.lua util/dns.lua

EXTRA_DIST = monitor.lua forge-dns.lua quiet.lua forge-reset.lua	\
	zeromq.lua redis.lua json.lua amqp-topic.lua protobuf.lua	\
	grpc.lua pulsar.lua util/addresses.lua util/json.lua		\
	util/dns.lua
EXTRA_DIST += cyberprobe.cfg

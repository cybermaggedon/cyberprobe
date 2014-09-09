
############################################################################
# Dump a Cybox observable
############################################################################

def dump_indicator(ind):
    
    # Dump stuff out
    if ind.id_:
        print "Id: %s" % ind.id_
    if ind.description:
        print "Description: %s" % ind.description

    # Get object
    obs = ind.observable
    obj = obs.object_.properties

    if isinstance(obj, Address):

        print "Address:"
        if obj.category == Address.CAT_EMAIL:
            print '  Email address: %s' % obj.address_value
        if obj.category == Address.CAT_IPV4:
            print '  IPv4 address: %s' % obj.address_value
        if obj.category == Address.CAT_MAC:
            print '  MAC address: %s' % obj.address_value

    if isinstance(obj, File):
        print "File:"

        if obj.full_path:  print "  Path: %s" % obj.full_path

        if obj.hashes:
            for h in obj.hashes:
                print "  Hash: "
                if h.simple_hash_value:
                    print "    Simple hash: %s" % h.simple_hash_value
                if h.fuzzy_hash_value:
                    print "    Fuzzy hash: %s" % h.fuzzy_hash_value
                if h.type_:
                    print "    Type: %s" % h.type_

    if isinstance(obj, Hostname):
        print "Hostname: %s" % obj.hostname_value

    if isinstance(obj, Port):
        print "Port: %s (%s)" % (obj.port_value, obj.layer4_protocol)

    if isinstance(obj, URI):
        print "URI: %s" % obj.value

    if isinstance(obj, UserAccount):
        print "User account:"
        print "  Username: %s" % obj.username
        print "  Domain: %s" % obj.domain

    print

############################################################################
# Dump a STIX package in human readable form
############################################################################

def dump_package(pkg):

    print

    # Walk through indicators
    for ind in pkg.indicators:
        dump_indicator(ind)

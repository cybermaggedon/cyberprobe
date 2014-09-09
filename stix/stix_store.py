
from gmt import GMT
import os
import datetime
from stix.core import STIXPackage
import StringIO
from lxml import etree

############################################################################
# STIX store
############################################################################
class STIXStore:

    def __init__(s, directory):
        s.directory = directory

    # Apply a query criterion
    def apply_query_criterion(s, criterion, doc):

        # Namespaces we'll use later
        namespaces = {
            "cybox": "http://cybox.mitre.org/cybox-2",
            "AddressObj": "http://cybox.mitre.org/objects#AddressObject-2",
            "stix": "http://stix.mitre.org/stix-1",
            "stixCommon": "http://stix.mitre.org/common-1",
            "HostnameObj": "http://cybox.mitre.org/objects#HostnameObject-1",
            "PortObj": "http://cybox.mitre.org/objects#PortObject-2",
            "cyboxCommon": "http://cybox.mitre.org/common-2"
        }

        # Convert target to XPath pointer part
        if criterion.target == '//Address_Value':
            expr = '//AddressObj:Address_Value'
        elif criterion.target == '//Indicator/@id':
            expr = '//stix:Indicator/@id'
        elif criterion.target == '//Package_Intent':
            expr = '//stix:Package_Intent'
        elif criterion.target == '//Object/Properties/@category':
            expr = '//cybox:Object/cybox:Properties/@category'
        elif criterion.target == '//Hostname_Value':
            expr = '//HostnameObj:Hostname_Value'
        elif criterion.target == '//Port_Value':
            expr = '//PortObj:Port_Value'
        elif criterion.target == '//Hash/Simple_Hash_Value':
            expr = '//cyboxCommon:Hash/cyboxCommon:Simple_Hash_Value'
        elif criterion.target == '/STIX_Package/@id':
            expr = '/stix:STIX_Package/@id'
        elif criterion.target == '//Information_Source/Identity/@idref':
            expr = '//stix:Information_Source/stixCommon:Identity/@idref'

        relationship = criterion.test.relationship
        params = criterion.test.parameters
        value = params['value']

        if relationship == 'equals':
            if params['match_type'] == 'case_sensitive_string':
                expr +=  '[. = "%s"]' % value
            elif params['match_type'] == 'case_insensitive_string':
                expr += '[translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz") = "%s"]' % value.lower()
            elif params['match_type'] == 'number':
                expr += '[. = "%s"]' % value
        elif relationship == 'not equals':
            if params['match_type'] == 'case_sensitive_string':
                expr += '[. != "%s"]' % value
            elif params['match_type'] == 'case_insensitive_string':
                expr += '[translate(%s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz") != "%s"]' % value
            elif params['match_type'] == 'number':
                expr += '[. != "%s"]' % value
        elif relationship == 'greater than':
            expr += '[. > "%s"]' % value
        elif relationship == 'greater than or equal':
            expr += '[. >= "%s"]' % value
        elif relationship == 'less than':
            expr += '[. < "%s"]' % value
        elif relationship == 'less than or equal':
            expr += '[. <= "%s"]' % value
        elif relationship == 'does not exist':
            expr = "not(%s)" % expr
        elif relationship == 'exists':
            # Complete
            pass
        elif relationship == 'begins with':
            if params['case_sensitive'] == 'false':
                expr += '[starts-with(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "%s")]' % value
            elif params['case_sensitive'] == 'true':
                expr += '[starts-with(., "%s")]' % value
        elif relationship == 'ends with':
            if params['case_sensitive'] == 'false':
                expr += '[substring(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), string-length(.) - string-length("%s") + 1) = "%s"]' % (value, value.lower())
        elif params['case_sensitive'] == 'true':
            expr += '[substring(., string-length(.) - string-length("%s") + 1) = "%s"]' % (value, value.lower())
        elif relationship == 'contains':
            if params['case_sensitive'] == 'false':
                expr += '[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "%s")]' % value()
            elif params['case_sensitive'] == 'true':
                expr += '[contains(., "%s")]' % value()
        
        result = doc.xpath(expr, namespaces=namespaces)

        #print expr
        
        if result == True:
            ret = True
        elif result == False:
            ret = False
        elif len(result) > 0:
            ret = True
        else:
            ret = False

        if criterion.negate:
            return not ret
        else:
            return ret

    # Apply a query criteria
    def apply_query_criteria(s, criteria, doc):

        for c in criteria.criteria:
            ret = s.apply_query_criteria(c, doc)
            if criteria.operator == 'AND' and ret == False:
                return False
            if criteria.operator == 'OR' and ret == True:
                return True

        for c in criteria.criterion:
            ret = s.apply_query_criterion(c, doc)
            if criteria.operator == 'AND' and ret == False:
                return False
            if criteria.operator == 'OR' and ret == True:
                return True

        if criteria.operator == 'AND':
            return True

        return False

    def get_collections(s):
        return os.listdir(s.directory)

    def get_documents(s, collection):
        path = os.path.join(s.directory, collection)
        return os.listdir(path)

    def get_document_paths(s, collection):
        path = os.path.join(s.directory, collection)
        files = os.listdir(path)

        fullpath = lambda x: os.path.join(s.directory, collection, x)
        return map(fullpath, files)

    def get_matching(s, collection, begin, end, query, fn):

        flst = s.get_document_paths(collection)

        # Get the time (now)
        now = datetime.datetime.now(GMT())

        # Start constructing the content block list
        matches = []

        # Need to record the newest timestamp of all the data files, this 
        # variable keeps track.
        latest = None

        # Iterate over file list.
        for file in flst:

            # Stat in order to get the last modification time.
            st = os.stat(file)
            then = datetime.datetime.fromtimestamp(st.st_mtime, GMT())

            # Check whether file's modification time falls within the
            # begin/end bounds.
            if begin:
                if begin >= then:
                    continue
            if end:
                if end < then:
                    continue

            # Open the file and read contents.
            f = open(file, "r")
            content = f.read()
            f.close()

            if query != None:

                # Parse XML
                doc = etree.parse(StringIO.StringIO(content))

                ret = s.apply_query_criteria(query.criteria, doc)

                if not ret:
                    continue

            # Keep the 'latest' time up to date.
            if latest == None or then > latest:
                latest = then

            fn(content, file)

        # If there's no latest (i.e. there were no content blocks in scope,
        # then use current time.
        if latest == None:
            latest = now

        return latest

    def add_content(s, content, collection):

        # Hack an XML header on the top?! and add the payload body.
#        content = "<?xml version=\"1.0\"?>\n" + content

        # Parse the payload, should be a STIX document.
        package = STIXPackage.from_xml(StringIO.StringIO(content))

        # FIXME: Make sure this can't be used to write an arbitrary
        # file.
        path = os.path.join(s.directory, collection, package.id_)

        f = open(path, 'w')
        f.write(content)
        f.close()

        print "Wrote %s" % path

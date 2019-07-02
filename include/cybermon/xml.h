
#ifndef XML_H
#define XML_H

#include <string>
#include <list>
#include <map>
#include <stack>
#include <iterator>

#include <expat.h>

using namespace std;

/*
  Converts XML into an element tree.  Pretty basic.
*/

namespace xml {

    class element;

    static const string hard_charset = "iso-8859-1";

    /* Functor class, accepts find events. */
    class find_event_receiver {
    public:
	virtual void operator()(element&) {}
        virtual ~find_event_receiver() {}
    };

    /* An element. */
    class element {
    public:

	/** Whether to transmit this element as CDATA */
	bool cdata;

	/* Element name */
        std::string name;

	/* Style */
	std::string style;

	/* Map of attribute name to value */
	map<std::string,std::string> attributes;

	/* Any text contained within the element */
	std::string text;

	/* A list of child elements */
	list<element> children;

	element& add(const std::string& name) {

	    // Try this - otherwise weird things happen?
	    element e;
	    e.name = name;
	    children.push_back(e);
	    return children.back();

            /*
              children.push_back(element());
              children.back().name = name;
              return children.back();
            */
	}

	element& add_cdata(const std::string& name) {
	    element& e = add(name);
	    e.cdata = true;
	    return e;
	}

	element& add(const std::string& name, const std::string& text) {
	    children.push_back(element());
	    children.back().name = name;
	    children.back().text = text;
	    return children.back();
	}

	element& add_cdata(const std::string& name, const std::string& text) {
	    element& e = add(name, text);
	    e.cdata = true;
	    return e;
	}

	element* parent;

	element& get(const std::string& name);

	element& get(const std::string& attribute, 
		     const std::string& value);

	element& locate(const std::string& name);

	element& locate(const std::string& attribute, 
			const std::string& value);

	void erase(const std::string& name);
	
	void erase(const std::string& attribute, const std::string& value);

	element() { parent = 0; cdata = false; }

	void locate(const std::string& name, find_event_receiver&);

	void locate(const std::string& name, 
		    std::back_insert_iterator< std::list<element*> >);

	void output(ostream& output);
	static void output(list<element*>& elts, ostream& output);

	virtual ~element() {}

    };

    /*

      An XML decoder.  Very basic.

      xml::decoder *dec = new xml::decoder;
      dec->parse(data, data_len);
      dec->parse(data, data_len);
      dec->parse(data, data_len);
      do_something(dec->root);
      delete dec;
    

    */
    class decoder {

    private:

	std::string text;
	XML_Parser parser;

	stack<element*> elements;
	
    public:

	/* Constructor */
	decoder();

	/* Destructor */
	virtual ~decoder();

	/* Once parsing has finished, this element can be used to access
	   the element tree. */
	element root;

	/* Parse some data */
	void parse(const unsigned char *data, int len);
	void parse(const std::string& s) {
	    parse((const unsigned char*) s.c_str(), s.length());
	}

	/* Don't use these are callbacks for the XML parser */
	static void start_element_handler(void *user, 
					  const XML_Char *name, 
					  const XML_Char **attrs);
	static void character_handler(void *user, 
				      const XML_Char *name, 
				      int len);
	static void end_element_handler(void *user, 
					const XML_Char *name);
	
    };

}

#endif


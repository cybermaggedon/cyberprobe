
#include <sstream>
#include <iostream>
#include <exception>
#include <stdexcept>

#include <expat.h>

#include <cybermon/xml.h>

using namespace xml;

void decoder::start_element_handler(void *user, 
                                    const XML_Char *name, 
                                    const XML_Char **attrs)
{

    decoder *t = ((decoder *) user);

    // Current item.
    element& cur = *(t->elements.top());

    // Create new child.
    cur.children.push_back(element());
    element& newelt = cur.children.back();
    newelt.parent = &cur;

    // Add new info.
    newelt.name = name;
    for(int i = 0; attrs[i] != 0; i += 2)
	newelt.attributes[attrs[i]] = attrs[i+1];

    t->elements.push(&newelt);

}

void decoder::end_element_handler(void *user, 
                                  const XML_Char *name)
{

    decoder *t = ((decoder *) user);
    t->elements.pop();

}

void decoder::character_handler(void *user, 
                                const XML_Char *text, 
                                int len)
{

    decoder *t = ((decoder *) user);
    element& cur = *(t->elements.top());
    cur.text.append(text, len);

}

void decoder::parse(const unsigned char *data, int len)
{

    enum XML_Status status;
    status = 
	XML_Parse(parser, (const char *) data, len, 0);
    if (status == XML_STATUS_ERROR) {
	enum XML_Error code = XML_GetErrorCode(parser);

	ostringstream o;
	o << "XML parse error: at pos=" 
	  << XML_GetCurrentByteIndex(parser) << " " 
	  << XML_ErrorString(code);
	throw logic_error(o.str());
    }


}

decoder::decoder() 
{

    //    parser = XML_ParserCreateNS(0, '@');
    parser = XML_ParserCreate(0);
    if (parser == 0)
	throw runtime_error("Failed to create parser");
    XML_SetUserData(parser, this);
    XML_SetStartElementHandler(parser, decoder::start_element_handler);
    XML_SetCharacterDataHandler(parser, decoder::character_handler);
    XML_SetEndElementHandler(parser, decoder::end_element_handler);

    elements.push(&root);

}

decoder::~decoder() 
{

    // FIXME: Why is this here?
    //	XML_Parse(parser, NULL, 0, 1);
    XML_ParserFree(parser);

}

void element::erase(const std::string& name)
{

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {

	if (e->name == name) {
	    children.erase(e);
	    return;
	}
	e->erase(name);
	
    }

}

void element::erase(const std::string& attribute, const std::string& value)
{

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {

	for(map<std::string,std::string>::iterator i = e->attributes.begin();
	    i != e->attributes.end();
	    i++) {
	    if (i->first == attribute && i->second == value) {
		children.erase(e);
		return;
	    }
	    e->erase(attribute, value);
	}

    }

}

element& element::locate(const std::string& name)
{

    if (this->name == name) {
	return *this;
    }

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {

	try {
	    return e->locate(name);
	} catch (out_of_range& e) {
	    // Not on this child, carry on.
	}
	
    }

    // Not here.
    throw std::out_of_range("Not found");

}

element& element::locate(const std::string& attr, const std::string& value)
{

    for(map<std::string,std::string>::iterator i = attributes.begin();
	i != attributes.end();
	i++) {
	if (i->first == attr && i->second == value) {
	    return *this;
	}
    }

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {

	try {
	    return e->locate(attr, value);
	} catch (out_of_range& e) {
	    // Not on this child, carry on.
	}
	
    }

    // Not here.
    throw std::out_of_range("No match for attribute '" + attr + "'");

}

void element::locate(const std::string& name, find_event_receiver& f)
{

    if (this->name == name) {
        f(*this);
    }

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {
	
        e->locate(name, f);
    }

}

void element::locate(const std::string& name, 
		     std::back_insert_iterator< std::list<xml::element*> > i)
{

    if (this->name == name) {
	*i = this;
    }

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {
	
        e->locate(name, i);
    }
}

element& element::get(const std::string& name)
{

    for(list<element>::iterator e = children.begin();
	e != children.end();
	e++) {

	if (e->name == name)
	    return *e;
	
    }

    // Not here.
    throw std::out_of_range("Element " + name + " not found");

}

element& element::get(const std::string& attr, const std::string& value)
{

    for(map<std::string,std::string>::iterator i = attributes.begin();
	i != attributes.end();
	i++) {
	if (i->first == attr && i->second == value) {
	    return *this;
	}
    }

    // Not here.
    throw std::out_of_range("No match for attribute '" + attr + "'");

}

void element::output(std::ostream& out)
{

    /* The tree walker maintains a "stack" of the elements which are
       currently in play. */
    list<element*> elts;

    /* XML intro */
    out << "<?xml version=\"1.0\" encoding=\"" << hard_charset 
        << "\" standalone=\"no\"?>"
        << endl;

    if (style != "")
        out << "<?xml-stylesheet type=\"text/xsl\" href=\"" << style 
            << "\"?>" << endl;

    out << endl;

    /* Put new element on stack, call the function which does the
       real work. */
    elts.push_back(this);

    output(elts, out);

    out << endl;

}

/* Outputs appropriate meta-data from the tree */
void element::output(list<element*>& elts, std::ostream& out)
{

    element* last = *(--elts.end());
    
    int depth = elts.size() - 2;

    if (last->name != "") {

	for(int i = 0; i < 2 * depth; i++)
	    out << "  ";

	out << "<" << last->name;

	map<string,string>::iterator i;
	for(i = last->attributes.begin();
	    i != last->attributes.end();
	    i++) {
	    out << " " << i->first << "=\"";
	    for(unsigned int j = 0; j < i->second.size(); j++) {
                unsigned char c = i->second[j];
                if (c == '<')
                    out << "&lt;";
                else if (c == '>')
                    out << "&gt;";
                else if (c == '&')
                    out << "&amp;";
                else out << c;
	    }
	    out << "\"";
	}

	if (last->children.size() == 0 &&
	    last->text == "") {
	    out << "/>\n";
	    return;
	}

	out << ">";

	while (last->text[0] == ' ' ||
	       last->text[0] == '\t' ||
	       last->text[0] == '\n')
	    last->text = last->text.substr(1);

	
	if (last->cdata) {
	    out << "<![CDATA[" << last->text << "]]>" << endl;
	} else {
	    
	    if (last->text != "") {
		for(unsigned int i = 0; i < last->text.size(); i++) {
		    unsigned char c = last->text[i];
		    if (c == '<')
			out << "&lt;";
		    else if (c == '>')
			out << "&gt;";
		    else if (c == '&')
			out << "&amp;";
		    else out << c;
		}
	    }

	}
	    
	if (last->children.size() != 0)
	    out << "\n";

    }

    /* Recursively call myself on children. */
    for(list<element>::iterator i = last->children.begin();
	i != last->children.end();
	i++) {
        element& child = *i;
	elts.push_back(&child);
	output(elts, out);
	elts.pop_back();
    }

    if (last->name != "") {

	if (last->children.size() != 0) {
	    for(int i = 0; i < 2 * depth; i++)
		out << "  ";
	}

	out << "</" << last->name << ">\n";

    }

}

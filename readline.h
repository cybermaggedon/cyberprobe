
#include <curses.h>
#include <term.h>

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>

#include <string>
#include <stdexcept>
#include <list>
#include <iostream>
#include <vector>

class readline {

public:

    static void init() {
	static bool i = false;
	if (i) return;
	if (getenv("TERM") == 0)
	    throw std::runtime_error("TERM variable is not set.");
	setupterm(getenv("TERM"), 1, 0);
	i = true;
    }

    readline() {
	init();
    }

    readline(const std::string& name) { 
	rl_readline_name = name.c_str(); 
	init();
    }

    static void blanked_password_redisplay() {

	std::string prompt = rl_prompt;
	std::string line_buf = rl_line_buffer;

	// Carriage return.
	putp(tigetstr((char*)"cr"));

	// Prompt;
	std::cout << prompt;

	// Output line buffer, replaced with '*' characters.
	for(unsigned int i = 0; i < line_buf.size(); i++)
	    std::cout << "*";

	// Clear to end of line.
	putp(tigetstr((char*)"el"));

	// Now move cursor backward into correct position.
	for(int i = 0; i < (rl_end - rl_point); i++)
	    putp(tigetstr((char*)"cub1"));

	// Flush out.
	std::cout.flush();

    }

    typedef
	bool (*generator_fn)(const std::string& partial, std::string& match);

    static generator_fn generator;

    static char* generator_wrapper(const char* text, int state) {
	
	std::string rtn;
	bool success = (*generator)(std::string(text), rtn);

	if (success)
	    return strdup(rtn.c_str());
	else
	    return 0;

    }


    static void make_completions(std::vector<std::string>& completions,
				 const std::string& token,
				 generator_fn gen) {
	
	generator = gen;
	completions.clear();

	char** c = rl_completion_matches(token.c_str(), generator_wrapper);

	if (c == 0)
	    return;

	for(int i = 0; c[i] != 0; i++) {
	    completions.push_back(std::string(c[i]));
	    free(c[i]);
	}

	free(c);

    }


    typedef void (*completer_fn)(const std::vector<std::string>& tokens,
				 const std::string& token,
				 int cur_token,
				 std::vector<std::string>& completions);

    static completer_fn completion;

    static char** completion_wrapper(const char* text, int start, int end) {

	std::vector<std::string> tokens;
	int cur_token = -1;

	unsigned int pos = 0;

	std::string buf = rl_line_buffer;

	std::string token;

	while (pos < buf.size()) {
	    if ((int) pos == start)
		cur_token = tokens.size();
	    
	    bool whitespace = (buf[pos] == ' ') || (buf[pos] == '\t');

	    if (whitespace) {
		if (token != "") {
		    tokens.push_back(token);
		    token = "";
		}
		pos++;
		continue;
	    }

	    token += buf[pos++];
	
	}
	
	if ((int) pos == start)
	    cur_token = tokens.size();
	
	if (token != "") tokens.push_back(token);

	std::vector<std::string> completions;

	std::string this_token = text;
	(*completion)(tokens, this_token, cur_token, completions);

	char** rtn;

	if (completions.size() == 0)
	    return 0;
	else {
	    rtn = (char**) malloc(sizeof(char*) * (completions.size() + 1));

	    unsigned int i;
	    for(i = 0; i < completions.size(); i++) {
		rtn[i] = strdup(completions[i].c_str());
	    }
	    rtn[i] = 0;

	}

	return rtn;

    }

    static void force_display_update() {
	rl_forced_update_display();
    }

    static void completion_over() {
	rl_attempted_completion_over = 1;
    }

    static void get_line_completing(const std::string& prompt, std::string& val,
				    completer_fn c) {

	rl_attempted_completion_function = &completion_wrapper;
	completion = c;

	get_line(prompt, val);

	rl_attempted_completion_function = 0;

    }

    static void get_line(const std::string& prompt, std::string& val) {
	char* f = ::readline(prompt.c_str());
	if (f == 0)
	    throw std::out_of_range("EOF");

	if (*f != 0)
	    ::add_history(f);

	val = f;
	::free(f);

    }

    static void get_password(const std::string& prompt, std::string& val) {

	rl_redisplay_function = &blanked_password_redisplay;

	char* f = ::readline(prompt.c_str());
	if (f == 0)
	    throw std::out_of_range("EOF");

	rl_redisplay_function = &rl_redisplay;

	val = f;
	::free(f);

    }

};



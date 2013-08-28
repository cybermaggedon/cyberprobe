
#include <curses.h>
#include <term.h>

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>

#include <string>
#include <stdexcept>

#include <iostream>

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



CXXFLAGS = --std=c++14 -Wall -Werror -pedantic -g

# Compile the main executable
nameserver: nameserver.cpp 
	g++ $(CXXFLAGS) nameserver.cpp -o nameserver

# Remove automatically generated files
clean :
	rm -rvf *.exe *~ *.out *.dSYM *.stackdump nameserver

# Disable built-in rules
.SUFFIXES:

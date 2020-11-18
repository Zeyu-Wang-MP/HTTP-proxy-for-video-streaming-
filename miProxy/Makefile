
CXXFLAGS = --std=c++14 -Wall -Werror -pedantic -g 

all: main.cpp proxy.o
	g++ $(CXXFLAGS) -o miProxy $^ -pthread

proxy.o: proxy.cpp
	g++ $(CXXFLAGS) -c -o $@ $^ -pthread

clean:
	rm -rf *.o miProxy


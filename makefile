

CC=gcc
CXX=g++
CFLAGS=-g
CXXFLAGS=-g
# Add -lcrypto to link with OpenSSL's libcrypto
LDFLAGS=-lcrypto
EXECUTABLE=Main
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
CPPSOURCES=$(wildcard *.cpp)
CPPOBJECTS=$(CPPSOURCES:.cpp=.o)

all: $(EXECUTABLE)

# Ensure the object files come before LDFLAGS
$(EXECUTABLE): $(OBJECTS) $(CPPOBJECTS)
	$(CXX) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS) $(CPPOBJECTS)


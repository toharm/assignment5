CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-deprecated-declarations
BOOST    := $(shell brew --prefix boost 2>/dev/null)
OPENSSL  := $(shell brew --prefix openssl@3 2>/dev/null)

CXXFLAGS += -I$(BOOST)/include -I$(OPENSSL)/include
LDFLAGS  += -L$(OPENSSL)/lib -lcrypto

all: crypto

crypto: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o crypto $(LDFLAGS)

run: crypto
	./crypto

clean:
	rm -f crypto

SOURCE := algorand.cpp base.cpp mnemonic.cpp

# Build dependencies, expressed for brew on MacOS
#
# brew install libsodium msgpack openssl rapidjson


# On MacOS, brew installed openssl does not end up in system
# locations, so we need to be explicit.
IFLAGS += -I/usr/local/opt/openssl/include
LFLAGS += -L/usr/local/opt/openssl/lib

LIBS   += -lcurl -lsodium -lcrypto

CC = c++
CCFLAGS += -std=c++14

.cpp.o:
	$(CC) $(CCFLAGS) $(IFLAGS) -c $<

example: $(subst .cpp,.o,$(SOURCE)) example.o
	$(CC) $(CCFLAGS) $(LFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f $(subst .cpp,.o,$(SOURCE)) example.o example

$(subst .cpp,.o,$(SOURCE)): algorand.h
example.o: algorand.h

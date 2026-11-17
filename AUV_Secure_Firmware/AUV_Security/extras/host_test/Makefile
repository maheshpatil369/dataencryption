# Host build of the AUV_Security test-suite.
# CRYPTO = path to rweather/arduinolibs (git clone https://github.com/rweather/arduinolibs)
CRYPTO ?= $(HOME)/arduinolibs
CRYPTO_SRC = $(CRYPTO)/libraries/Crypto
SRCS = AES256.cpp AESCommon.cpp GCM.cpp GHASH.cpp GF128.cpp BlockCipher.cpp Cipher.cpp \
       AuthenticatedCipher.cpp Crypto.cpp SHA256.cpp Hash.cpp
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -DHOST_BUILD \
           -I$(CRYPTO)/host/emulation -I$(CRYPTO_SRC) -I../../src
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer

auv_host_test: host_main.cpp $(addprefix $(CRYPTO_SRC)/,$(SRCS)) ../../src/*.h ../../examples/AUV_SelfTest/AUV_TestSuite.h
	$(CXX) $(CXXFLAGS) $(SAN) -o $@ host_main.cpp $(addprefix $(CRYPTO_SRC)/,$(SRCS))

clean:
	rm -f auv_host_test interop_peer payload_gen

CRYPTO_CPP = $(addprefix $(CRYPTO_SRC)/,$(SRCS))
interop_peer: interop_peer.cpp
	$(CXX) -std=c++17 -O2 -DHOST_BUILD -I$(CRYPTO)/host/emulation -I$(CRYPTO_SRC) -I../../src -o $@ $< $(CRYPTO_CPP)
payload_gen: payload_gen.cpp
	$(CXX) -std=c++17 -O2 -DHOST_BUILD -I$(CRYPTO)/host/emulation -I$(CRYPTO_SRC) -I../../src -o $@ $< $(CRYPTO_CPP)
check: auv_host_test interop_peer payload_gen
	./auv_host_test && python3 interop_test.py && python3 payload_test.py

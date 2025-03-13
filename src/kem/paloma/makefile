PALOMA_SECURITY_LEVEL ?= 256
WORD ?= 64
WITH_OPENSSL ?= 0

EXECUTABLE = paloma_run

# CC = arm-none-eabi-gcc
# CC = c++
CC = gcc
CFLAGS = -O3 -Wall -fPIC -fPIE -fwrapv -march=native

ifeq ($(PALOMA_SECURITY_LEVEL),128)
    CFLAGS += -DPALOMA_SECURITY_LEVEL=128
else ifeq ($(PALOMA_SECURITY_LEVEL),192)
    CFLAGS += -DPALOMA_SECURITY_LEVEL=192
else ifeq ($(PALOMA_SECURITY_LEVEL),256)
    CFLAGS += -DPALOMA_SECURITY_LEVEL=256
else
    $(error Invalid value for PALOMA_SECURITY_LEVEL. Please use 128, 192, or 256.)
endif

ifeq ($(WORD),32)
    CFLAGS += -DWORD=32
else ifeq ($(WORD),64)
    CFLAGS += -DWORD=64
else
    $(error Invalid value for WORD. Please choose one in {8, 32, 64})
endif



PALOMA_DIR          =   paloma/
COMMON_SRC_FILES    =   utility.c \
                        gf2m.c gf2m_poly.c \
                        mat_mul.c \
                        lsh.c lsh512.c \
                        paloma_api.c \
                        genkeypair.c \
                        encrypt.c encap.c \
                        decrypt.c decoding.c decap.c \
                        gf2m_tab.c \

ifeq ($(WITH_OPENSSL),1)
    CFLAGS += -DWITH_OPENSSL=1
    CFLAGS += -I$(shell brew --prefix openssl)/include
    LDFLAGS = -L$(shell brew --prefix openssl)/lib
    LIBS =  -lssl -lcrypto
    COMMON_SRC_FILES += aes256_ctr_drbg.c
endif


SRC_FILES = $(addprefix $(PALOMA_DIR), $(COMMON_SRC_FILES)) main_kat.c

all: $(EXECUTABLE)

# $(EXECUTABLE): $(SRC_FILES)
# 	$(CC) $(CFLAGS) -o $@ $^

$(EXECUTABLE): $(SRC_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)


clean:
	rm -f $(EXECUTABLE)
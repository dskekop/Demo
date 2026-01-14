CXX ?= g++
CC ?= gcc
AR ?= ar
CROSS ?=

ifeq ($(CROSS),)
TOOLCHAIN_PREFIX ?=
else
TOOLCHAIN_PREFIX := $(CROSS)
endif

ifeq ($(TOOLCHAIN_PREFIX),)
TOOLCHAIN_PREFIX ?=
endif

CXX := $(if $(TOOLCHAIN_PREFIX),$(TOOLCHAIN_PREFIX)g++,$(CXX))
CC := $(if $(TOOLCHAIN_PREFIX),$(TOOLCHAIN_PREFIX)gcc,$(CC))

CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CFLAGS += -Iinclude -pthread
CXXFLAGS ?= -std=gnu++11 -O2 -Wall -Wextra -Wpedantic
CXXFLAGS += -Iinclude -pthread
LDFLAGS ?=
LDLIBS ?=
LDLIBS += -pthread

COMMON_C_SRCS := \
	common/td_logging.c \
	common/td_config.c \
	common/terminal_manager.c \
	common/terminal_netlink.c

COMMON_CPP_SRCS := \
	common/terminal_northbound.cpp

COMMON_OBJS := $(COMMON_C_SRCS:.c=.o) $(COMMON_CPP_SRCS:.cpp=.o)
COMMON_LIB := libtd_common.a

ADAPTER_REALTEK_SRCS := \
	adapter/adapter_registry.c \
	adapter/realtek_adapter.c \
	stub/td_switch_mac_stub.c

ADAPTER_REALTEK_OBJS := $(ADAPTER_REALTEK_SRCS:.c=.o)

APP_SRCS := main/terminal_main.c
APP_OBJS := $(APP_SRCS:.c=.o)

TARGET := terminal_discovery

TEST_TARGET := terminal_discovery_tests
TEST_SRCS := tests/terminal_manager_tests.c
TEST_OBJS := $(TEST_SRCS:.c=.o)

INTEGRATION_TEST_TARGET := terminal_integration_tests
INTEGRATION_TEST_SRCS := tests/terminal_integration_tests.cpp
INTEGRATION_TEST_OBJS := $(INTEGRATION_TEST_SRCS:.cpp=.o)

STUB_TEST_TARGET := td_switch_mac_stub_tests
STUB_TEST_SRCS := tests/td_switch_mac_stub_tests.c
STUB_TEST_OBJS := $(STUB_TEST_SRCS:.c=.o)

EMBED_TEST_TARGET := terminal_embedded_init_tests
EMBED_TEST_SRCS := tests/terminal_embedded_init_tests.c
EMBED_TEST_OBJS := $(EMBED_TEST_SRCS:.c=.o) tests/terminal_main_for_tests.o

all: $(TARGET)

common-lib: $(COMMON_LIB)

$(TARGET): $(APP_OBJS) $(COMMON_LIB) $(ADAPTER_REALTEK_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(COMMON_LIB): $(COMMON_OBJS)
	$(AR) rcs $@ $^

$(TEST_TARGET): $(TEST_OBJS) $(COMMON_LIB)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(INTEGRATION_TEST_TARGET): $(INTEGRATION_TEST_OBJS) $(COMMON_LIB)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(STUB_TEST_TARGET): $(STUB_TEST_OBJS) stub/td_switch_mac_stub.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EMBED_TEST_TARGET): $(EMBED_TEST_OBJS) common/td_config.o common/td_logging.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tests/terminal_main_for_tests.o: main/terminal_main.c
	$(CC) $(CFLAGS) -DTD_DISABLE_APP_MAIN -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(COMMON_LIB) \
		$(COMMON_OBJS) $(ADAPTER_REALTEK_OBJS) $(APP_OBJS) \
		$(TEST_TARGET) $(TEST_OBJS) \
		$(INTEGRATION_TEST_TARGET) $(INTEGRATION_TEST_OBJS) \
		$(STUB_TEST_TARGET) $(STUB_TEST_OBJS) \
		$(EMBED_TEST_TARGET) $(EMBED_TEST_OBJS)

cross:
	$(MAKE) TOOLCHAIN_PREFIX=mips-rtl83xx-linux- all

cross-generic:
	$(MAKE) TOOLCHAIN_PREFIX=mips-linux-gnu- all

.PHONY: all clean cross cross-generic test common-lib adapter-realtek

test: $(TEST_TARGET) $(INTEGRATION_TEST_TARGET) $(STUB_TEST_TARGET) $(EMBED_TEST_TARGET)
	./$(TEST_TARGET)
	./$(INTEGRATION_TEST_TARGET)
	./$(STUB_TEST_TARGET)
	./$(EMBED_TEST_TARGET)

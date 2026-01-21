# Netforward platform build (stubbed adapter/sidecar)

ROOT := $(abspath ../..)
SRC_DIR := $(ROOT)/src
OUT_DIR := $(ROOT)/out/netforward
OBJ_DIR := $(OUT_DIR)/obj
BIN_DIR := $(OUT_DIR)/bin
LIB_DIR := $(OUT_DIR)/lib
TEST_DIR := $(OUT_DIR)/tests

CROSS_PREFIX ?=
CC := $(CROSS_PREFIX)gcc
CXX := $(CROSS_PREFIX)g++
AR := $(CROSS_PREFIX)ar

CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CFLAGS += -I$(SRC_DIR)/include -pthread -DTD_ENABLE_ADAPTER_NETFORWARD -DTD_DEFAULT_ADAPTER=\"netforward\"
CXXFLAGS ?= -std=gnu++11 -O2 -Wall -Wextra -Wpedantic
CXXFLAGS += -I$(SRC_DIR)/include -pthread -DTD_ENABLE_ADAPTER_NETFORWARD -DTD_DEFAULT_ADAPTER=\"netforward\"
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
COMMON_C_OBJS := $(COMMON_C_SRCS:%.c=$(OBJ_DIR)/%.o)
COMMON_CPP_OBJS := $(COMMON_CPP_SRCS:%.cpp=$(OBJ_DIR)/%.o)
COMMON_OBJS := $(COMMON_C_OBJS) $(COMMON_CPP_OBJS)
COMMON_LIB := $(LIB_DIR)/libtd_common.a

ADAPTER_SRCS := \
	adapter/adapter_registry.c \
	adapter/netforward_adapter.c
ADAPTER_OBJS := $(ADAPTER_SRCS:%.c=$(OBJ_DIR)/%.o)

APP_SRCS := main/terminal_main.c
APP_OBJS := $(APP_SRCS:%.c=$(OBJ_DIR)/%.o)

SIDE_CAR_BIN := $(BIN_DIR)/netforward_sidecar_stub
SIDE_CAR_SRCS := stub/netforward_sidecar_stub.c
SIDE_CAR_OBJS := $(SIDE_CAR_SRCS:%.c=$(OBJ_DIR)/%.o)

TEST_TARGETS := \
	$(TEST_DIR)/terminal_discovery_tests \
	$(TEST_DIR)/terminal_integration_tests \
	$(TEST_DIR)/terminal_embedded_init_tests \
	$(TEST_DIR)/netforward_adapter_tests

TEST_C_SRCS := \
	tests/terminal_manager_tests.c \
	tests/terminal_embedded_init_tests.c \
	main/terminal_main.c \
	common/td_config.c \
	common/td_logging.c
TEST_CPP_SRCS := tests/terminal_integration_tests.cpp
TEST_OBJS := $(TEST_C_SRCS:%.c=$(OBJ_DIR)/%.o) $(TEST_CPP_SRCS:%.cpp=$(OBJ_DIR)/%.o)

BIN := $(BIN_DIR)/terminal_discovery

DIRS := $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR) $(TEST_DIR)

.PHONY: all clean test sidecar sidecar-stub cross cross-generic

all: $(BIN)

$(BIN): $(APP_OBJS) $(ADAPTER_OBJS) $(COMMON_LIB) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(COMMON_LIB): $(COMMON_OBJS) | $(LIB_DIR)
	$(AR) rcs $@ $^

$(SIDE_CAR_BIN): $(SIDE_CAR_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

sidecar: $(SIDE_CAR_BIN)

sidecar-stub: sidecar

$(TEST_DIR)/terminal_discovery_tests: $(OBJ_DIR)/tests/terminal_manager_tests.o $(COMMON_LIB) | $(TEST_DIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/terminal_integration_tests: $(OBJ_DIR)/tests/terminal_integration_tests.o $(COMMON_LIB) | $(TEST_DIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/terminal_embedded_init_tests: $(OBJ_DIR)/tests/terminal_embedded_init_tests.o $(OBJ_DIR)/tests/terminal_main_for_tests.o $(OBJ_DIR)/common/td_config.o $(OBJ_DIR)/common/td_logging.o | $(TEST_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/netforward_adapter_tests: $(OBJ_DIR)/tests/netforward_adapter_tests.o $(ADAPTER_OBJS) $(COMMON_LIB) | $(TEST_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/tests/terminal_main_for_tests.o: $(SRC_DIR)/main/terminal_main.c | $(OBJ_DIR)/tests
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DTD_DISABLE_APP_MAIN -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(DIRS):
	@mkdir -p $@

clean:
	rm -rf $(OUT_DIR)

cross:
	$(MAKE) CROSS_PREFIX=aarch64-none-linux-gnu- all

cross-generic:
	$(MAKE) CROSS_PREFIX=aarch64-linux-gnu- all

cross-generic-test:
	$(MAKE) CROSS_PREFIX=aarch64-linux-gnu- test

test: $(TEST_TARGETS)
	$(TEST_DIR)/terminal_discovery_tests
	$(TEST_DIR)/terminal_integration_tests
	$(TEST_DIR)/terminal_embedded_init_tests
	$(TEST_DIR)/netforward_adapter_tests

# Explicit fresh builds only. This recipe never invokes either resulting binary.
override .DEFAULT_GOAL := help
.SUFFIXES:

# Only H3_SOURCE and BUILD_ROOT select build inputs; inherited/command-line
# variables cannot substitute a compiler, shell, source set or bridge.
override SHELL := /bin/sh
override .SHELLFLAGS := -c
override PATH := /usr/bin:/bin:/usr/sbin:/sbin
override RECIPE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
override PROJECT_ROOT := $(abspath $(RECIPE_DIR)/..)

ifeq ($(strip $(H3_SOURCE)),)
$(error H3_SOURCE is required and must be absolute)
endif
ifeq ($(strip $(BUILD_ROOT)),)
$(error BUILD_ROOT is required and must be absolute)
endif
ifneq ($(words $(H3_SOURCE) $(BUILD_ROOT) $(RECIPE_DIR)),3)
$(error Source, build and adapter paths must not contain whitespace)
endif
ifeq ($(filter /%,$(H3_SOURCE)),)
$(error H3_SOURCE must be absolute)
endif
ifeq ($(filter /%,$(BUILD_ROOT)),)
$(error BUILD_ROOT must be absolute)
endif
ifeq ($(realpath $(H3_SOURCE)),)
$(error H3_SOURCE must name an existing selected source directory)
endif
override H3_SOURCE := $(realpath $(H3_SOURCE))
override BUILD_ROOT := $(abspath $(BUILD_ROOT))
ifeq ($(BUILD_ROOT),/)
$(error BUILD_ROOT cannot be the filesystem root)
endif
ifneq ($(filter $(H3_SOURCE) $(H3_SOURCE)/% $(PROJECT_ROOT)/target $(PROJECT_ROOT)/target/%,$(BUILD_ROOT)),)
$(error BUILD_ROOT must be outside the selected source and project target directory)
endif
ifneq ($(wildcard $(BUILD_ROOT)),)
$(error BUILD_ROOT must be a new private build directory, not an existing path)
endif
ifeq ($(realpath $(dir $(BUILD_ROOT))),)
$(error BUILD_ROOT parent must already exist)
endif
ifneq ($(abspath $(dir $(BUILD_ROOT))),$(realpath $(dir $(BUILD_ROOT))))
$(error BUILD_ROOT parent must be canonical, without symlink components)
endif

# These are the selected upstream Makefile's flags and complete CLI source set.
# Do not include its Makefile: its targets and implicit rules write in-place.
override CC := clang
override CFLAGS := -std=c11 -O3 -MMD -MP -Wall -Wextra -Wpedantic -Wshadow \
	-Wconversion -Wno-sign-conversion -D_DARWIN_C_SOURCE
override OBJCFLAGS := $(CFLAGS) -fobjc-arc
override FRAMEWORKS := -framework Foundation -framework Metal \
	-framework MetalPerformanceShaders -framework MetalPerformanceShadersGraph \
	-framework Accelerate
override LDLIBS := $(FRAMEWORKS) -licucore -lm
override NATIVE_C := h3.c h3_host.c h3_safetensors.c h3_weights.c h3_text_encoder.c \
	h3_dit_schedule.c h3_dit.c h3_video_vae.c h3_video_encoder.c \
	h3_audio_vae.c h3_ffmpeg.c h3_terminal.c h3_vision_encoder.c h3_multimodal.c \
	main.c h3_cli.c linenoise.c
override NATIVE_M := h3_metal.m h3_gpu.m h3_tokenizer.m
override NATIVE_OBJECTS := $(addprefix $(BUILD_ROOT)/obj/,$(NATIVE_C:.c=.o) $(NATIVE_M:.m=.o))
override BRIDGE := $(BUILD_ROOT)/obj/mil-h3-owned-helpers.o
override CODEC := $(BUILD_ROOT)/obj/h3_ffmpeg.o
override FIXTURE := $(BUILD_ROOT)/obj/mil-h3-real-codec-fixture.o
override HEADERS := $(wildcard $(H3_SOURCE)/*.h)
override BRIDGE_HEADER := $(RECIPE_DIR)h3_owned_helpers.h

.PHONY: help native real-codec-fixture prepare
help:
	@printf '%s\n' 'Explicit targets: native, real-codec-fixture' \
		'Each invocation requires a fresh absolute BUILD_ROOT; no binary is run.'

native: $(BUILD_ROOT)/bin/h3-owned
real-codec-fixture: $(BUILD_ROOT)/bin/mil-h3-real-codec-fixture

# mkdir without -p rejects concurrent reuse; umask protects every output.
prepare:
	@umask 077; mkdir "$(BUILD_ROOT)" && mkdir "$(BUILD_ROOT)/obj" "$(BUILD_ROOT)/bin"

$(BUILD_ROOT)/bin/h3-owned: $(NATIVE_OBJECTS) $(BRIDGE) | prepare
	$(CC) -o "$@" $^ $(LDLIBS)

# CPU plumbing only: no main.c, inference units, Objective-C, frameworks or weights.
$(BUILD_ROOT)/bin/mil-h3-real-codec-fixture: $(CODEC) $(BRIDGE) $(FIXTURE) | prepare
	$(CC) -o "$@" $^ -pthread -lm

$(BUILD_ROOT)/obj/h3_ffmpeg.o: $(H3_SOURCE)/h3_ffmpeg.c $(HEADERS) $(BRIDGE_HEADER) | prepare
	$(CC) $(CFLAGS) -I"$(H3_SOURCE)" -include "$(BRIDGE_HEADER)" -c "$<" -o "$@"

$(BUILD_ROOT)/obj/linenoise.o: $(H3_SOURCE)/linenoise.c $(HEADERS) | prepare
	$(CC) $(CFLAGS) -Wno-conversion -Wno-variadic-macro-arguments-omitted -I"$(H3_SOURCE)" -c "$<" -o "$@"

$(BUILD_ROOT)/obj/%.o: $(H3_SOURCE)/%.c $(HEADERS) | prepare
	$(CC) $(CFLAGS) -I"$(H3_SOURCE)" -c "$<" -o "$@"

$(BUILD_ROOT)/obj/%.o: $(H3_SOURCE)/%.m $(HEADERS) | prepare
	$(CC) $(OBJCFLAGS) -I"$(H3_SOURCE)" -c "$<" -o "$@"

# The bridge defines MIL_H3_BRIDGE_IMPLEMENTATION itself; never force-include it here.
$(BRIDGE): $(RECIPE_DIR)h3_owned_helpers.c $(BRIDGE_HEADER) | prepare
	$(CC) $(CFLAGS) -I"$(RECIPE_DIR)" -c "$<" -o "$@"

$(FIXTURE): $(RECIPE_DIR)h3_real_codec_fixture.c $(H3_SOURCE)/h3_ffmpeg.h $(BRIDGE_HEADER) | prepare
	$(CC) $(CFLAGS) -I"$(H3_SOURCE)" -c "$<" -o "$@"

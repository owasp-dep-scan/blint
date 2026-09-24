# Tier-1 planted-variant modules. Built by ndk-build from the real NDK;
# every module's flags ARE the expected fact (see 05-corpus.md tier 1):
#
#   hello        plain dynamic JNI library (also built unstripped/stripped
#                by ndk-build's two output trees)
#   hello_page4k -Wl,-z,max-page-size=4096  (4 KB page alignment)
#   hello_page16k -Wl,-z,max-page-size=16384 (16 KB page alignment)
#   hello_hwasan -fsanitize=hwaddress       (arm64-v8a only)
#   hello_memtag -Wl,-z,memtag-stack=async  (arm64-v8a only, NDK r27+)
#   hello_bti    -mbranch-protection=standard (arm64-v8a only; GNU property
#                 note with BTI)
#   hello_textrels  .word/.xword absolute reloc in .text + -Wl,-z,notext
#                 (DT_TEXTREL)
#   hello_static static PIE executable (no NEEDED / no interpreter)
#

LOCAL_PATH := $(call my-dir)

HELLO_SRC := hello.c blint_sink.c

include $(CLEAR_VARS)
LOCAL_MODULE := hello
LOCAL_SRC_FILES := $(HELLO_SRC)
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := hello_page4k
LOCAL_SRC_FILES := $(HELLO_SRC)
LOCAL_LDFLAGS := -Wl,-z,max-page-size=4096
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := hello_page16k
LOCAL_SRC_FILES := $(HELLO_SRC)
LOCAL_LDFLAGS := -Wl,-z,max-page-size=16384
include $(BUILD_SHARED_LIBRARY)

ifeq ($(TARGET_ARCH),arm64)
include $(CLEAR_VARS)
LOCAL_MODULE := hello_hwasan
LOCAL_SRC_FILES := $(HELLO_SRC)
LOCAL_CFLAGS := -fsanitize=hwaddress -fno-omit-frame-pointer
LOCAL_LDFLAGS := -fsanitize=hwaddress
include $(BUILD_SHARED_LIBRARY)
endif

ifeq ($(TARGET_ARCH),arm64)
include $(CLEAR_VARS)
LOCAL_MODULE := hello_memtag
LOCAL_SRC_FILES := $(HELLO_SRC)
# -fsanitize=memtag-stack with the +march emits the note at LINK time (the
# clang driver turns it into the linker flag that produces
# .note.android.memtag), so it must be in LDFLAGS too: ndk-build does not
# apply LOCAL_CFLAGS when linking. The -Wl,-z,memtag-stack=async form is
# not accepted by the NDK's lld (verified r27.3/r28.2: "unknown -z value").
LOCAL_CFLAGS := -march=armv8.5-a+memtag -fsanitize=memtag-stack
LOCAL_LDFLAGS := -march=armv8.5-a+memtag -fsanitize=memtag-stack
include $(BUILD_SHARED_LIBRARY)
endif

ifeq ($(TARGET_ARCH),arm64)
include $(CLEAR_VARS)
LOCAL_MODULE := hello_bti
LOCAL_SRC_FILES := $(HELLO_SRC)
LOCAL_CFLAGS := -mbranch-protection=standard
include $(BUILD_SHARED_LIBRARY)
endif

include $(CLEAR_VARS)
LOCAL_MODULE := hello_textrels
LOCAL_SRC_FILES := $(HELLO_SRC) textrels_$(TARGET_ARCH).S
LOCAL_LDFLAGS := -Wl,-z,notext
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := hello_static
LOCAL_SRC_FILES := hello_static.c
LOCAL_LDFLAGS := -static
include $(BUILD_EXECUTABLE)

/* textrel probe, aarch64: an absolute relocation inside .text.
   Assembled and linked by the real NDK toolchain with -Wl,-z,notext; the
   link is expected to set DT_TEXTREL (verified with llvm-readelf -d in the
   same corpus run). C-style comments because .S files run through the C
   preprocessor, where arch-specific comment characters are not uniform. */
    .text
    .globl textrel_probe
textrel_probe:
    .xword java_add_left
    ret

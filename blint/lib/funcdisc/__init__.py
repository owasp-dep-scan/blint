"""Function discovery for stripped native binaries.

blint historically enumerated functions only from symbol tables, so a stripped
binary yielded zero disassembly and therefore zero function reviews, implant
findings and callgraph edges. The modules in this package recover function
entry points from structures the runtime itself depends on and which therefore
survive ``strip``:

- ``unwind.py`` parses Mach-O ``__TEXT,__unwind_info`` (compact unwind) and
  ELF ``.eh_frame_hdr`` / ``.eh_frame`` into exact function starts and sizes.
- ``complete.py`` completes the discovered set with call-site promotion and a
  bounded prologue scan for formats without unwind tables (Go ELF, 32-bit PE).

Discovery is additive by contract: recovered entries never replace a real
symbol name, and merge semantics mirror ``merge_macho_function_starts``.
"""

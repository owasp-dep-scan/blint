import sys, json, hashlib
from blint.lib.binary import parse
from blint.lib.disassembler import disassemble_functions
from blint.lib.similarity import attach_function_hashes
import lief

target = sys.argv[1]
md = parse(target, disassemble=False)
parsed_obj = lief.MachO.parse(target).at(0)
md["disassembled_functions"] = disassemble_functions(parsed_obj, md)
attach_function_hashes(md.get("disassembled_functions"))
out = {}
for name, fn in (md.get("disassembled_functions") or {}).items():
    if isinstance(fn, dict) and fn.get("fuzzy_hash"):
        out[fn.get("name") or name] = [fn.get("fuzzy_hash"), fn.get("cfg_hash"), fn.get("import_hash")]
print(json.dumps({"count": len(out), "hashes": out}))

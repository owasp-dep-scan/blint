These JSON files are wasm-tools 2.2 reports of modules kept one directory up.
They let the tests exercise the 2.2 report shape (`body_offset`, `module_id`,
`core_module`, `from_module`, `to_module`, synthetic nodes, `canon` edges)
whichever wasm-tools release is installed.

Each file was written from the module of the same name in `tests/data` with
the `feature/2.2.0-roadmap` branch of wasm-tools (reports `2.2.0`):

    from wasm_tools.api import parse_wasm_file
    report = parse_wasm_file(path, include_strings=True, include_call_graph=True)
    report["file"] = os.path.basename(path)
    json.dump(report, fh, indent=1, sort_keys=True)

`wit_lift_lower.wasm` is the component fixture of the same name from the
wasm-tools repository. It has two core modules whose function index spaces
both start at 0. `complex_flow.wasm` is a core module and `component_minimal.wasm`
wraps one core module in a component.

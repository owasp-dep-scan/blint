# Generating spec.py

```shell
pip install "datamodel-code-generator[http]"
curl -sLO https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json
curl -sLO https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json
curl -sLO https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json
datamodel-codegen --input bom-1.7.schema.json --input-file-type jsonschema --output <tmp-dir> --output-model-type pydantic_v2.BaseModel --target-python-version 3.10 --use-annotated --class-name CycloneDX
```

The generator writes the root model to `<tmp-dir>/__init__.py`; copy it to
`blint/cyclonedx/spec.py` (keeping blint's re-export `__init__.py`) together
with `spdx.py`. The exact datamodel-codegen version is recorded in the
header of `spec.py`.

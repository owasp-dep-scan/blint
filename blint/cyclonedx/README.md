# Generating spec.py

```shell
pip install datamodel-code-generator
datamodel-codegen --input /mnt/work/CycloneDX/specification/schema/bom-1.5.schema.json --input-file-type jsonschema --output blint/cyclonedx/ --output-model-type pydantic_v2.BaseModel --target-python-version 3.10 --use-annotated --class-name CycloneDX
```

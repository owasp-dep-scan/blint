# Custom Properties

This page documents the custom properties that the AppThreat tooling adds to a CycloneDX BOM. blint is the producer of the BOM and emits most of these properties. atom-tools enriches the same BOM with reachability information derived from atom slices, and chen supplies the semantic tags that atom-tools turns into services and service properties. The goal of this document is to give a single technical reference for every non standard field, the object it appears on, the value encoding, when it is emitted, and how it can be used in analysis and policy.

These properties are specific to the AppThreat tools. They are not part of the CycloneDX core specification. They are intended to enrich analysis and policy decisions, and consumers should treat them as advisory enrichment rather than authoritative inventory.

## Scope

The properties described here are written by three tools that share one BOM.

blint parses the binary and Android artifacts and writes the component inventory together with the `internal:` and `internal.` properties. When deep mode is enabled it also parses the dex classes, which is what makes service detection and behavioural review possible. When disassembly is enabled it additionally writes a Dalvik callgraph sidecar next to the BOM.

atom-tools runs blint and atom, then merges the reachability evidence from atom into the BOM. It promotes the services that the application actually reaches into the `services` array and attaches reachability counts to them.

chen is the code property graph library used by atom. Its tagger passes attach semantic tags such as `pii`, `tracker`, and `service-egress` to the flows in a reachable slice. atom-tools reads those tags and converts them into CycloneDX services and the service level properties described later in this document.

## How to read these properties

CycloneDX custom properties are name and value pairs, so every value is serialized as a string even when it represents a boolean, a number, or a list. Consumers should assume string values and coerce them explicitly before comparison.

The value encodings used by these properties are summarized below.

| Shape                  | Encoding                                         | Examples                                          |
| ---------------------- | ------------------------------------------------ | ------------------------------------------------- |
| Boolean                | the strings `true` or `false`                    | `internal:onDeviceAi`                             |
| Number like            | a decimal string                                 | `internal:versionCode`, `internal:reachableFlows` |
| Single value           | a plain string                                   | `internal:minSdkVersion`, `internal:mainActivity` |
| Newline separated list | values joined by a newline                       | `internal.appPermissions`, `internal.appFeatures` |
| Delimited list         | values joined by the blint symbol delimiter `~~` | `internal:functions`, `internal:classes`          |
| Compound value         | fields joined by the pipe character              | `internal:behaviour:<ID>`                         |

Two namespaces are in use. The dotted namespace such as `internal.appPermissions` is the older form retained for the manifest derived application metadata. The colon namespace such as `internal:minSdkVersion` is the preferred form for everything added more recently. New properties should use the colon namespace.

## Application component properties

These properties appear on the parent application component, which is the component that represents the apk, the apkm bundle, or the aab. blint derives them from the decoded `AndroidManifest.xml` and, for split bundles, from the bundle `info.json`.

| Property                     | Object                | Value type   | When emitted                                         | What it captures                                                                                                |
| ---------------------------- | --------------------- | ------------ | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `internal.appPermissions`    | application component | newline list | When the manifest declares `uses-permission` entries | The full set of requested Android permissions. This is the primary input for dangerous permission review.       |
| `internal.appFeatures`       | application component | newline list | When the manifest declares `uses-feature` entries    | The hardware and software features the application requests.                                                    |
| `internal:versionCode`       | application component | number like  | When present in the manifest or bundle info          | The integer Android version code, which is more reliable than the display version for ordering builds.          |
| `internal:minSdkVersion`     | application component | single value | When the manifest declares a minimum SDK             | The lowest Android API level the application supports, which bounds the platform hardening that can be assumed. |
| `internal:targetSdkVersion`  | application component | single value | When the manifest declares a target SDK              | The API level the application targets, which controls many runtime security defaults.                           |
| `internal:compileSdkVersion` | application component | single value | When present in the manifest                         | The API level the application was compiled against.                                                             |
| `internal:mainActivity`      | application component | single value | When a launcher activity is found                    | The fully qualified launcher activity, useful as an entry point for review.                                     |
| `internal:appName`           | application component | single value | For apkm bundles that carry an `info.json`           | The human readable application name from the bundle metadata.                                                   |
| `internal:architectures`     | application component | comma list   | For apkm bundles that declare arches                 | The native architectures the bundle ships, which indicates the native attack surface present.                   |
| `internal:locales`           | application component | comma list   | For apkm bundles that declare languages              | The locales packaged in the bundle.                                                                             |
| `internal:densities`         | application component | comma list   | For apkm bundles that declare dpis                   | The screen densities packaged in the bundle.                                                                    |

## File and library component properties

These properties appear on the components that represent the files inside the application, which include native shared objects, dex files, and version stamped maven libraries. They record the discovery evidence and the extracted symbols.

| Property             | Object                         | Value type     | When emitted                                 | What it captures                                                                                                   |
| -------------------- | ------------------------------ | -------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `internal:srcFile`   | file component                 | single value   | On every file component                      | The path of the file inside the application archive, used as discovery evidence.                                   |
| `internal:appFile`   | file component                 | single value   | On every file component                      | The originating application file, which ties a split or nested artifact back to its parent.                        |
| `internal:functions` | dex or shared object component | delimited list | In deep mode for dex, and for shared objects | The method or function names extracted from the artifact. For dex this is the smali style method signature.        |
| `internal:classes`   | dex component                  | delimited list | In deep mode for dex files                   | The class names defined in the dex file. This is the signal that service detection and behavioural review consume. |

## Native binary symbol properties

When blint parses a native binary it records the symbol tables and import and export surfaces as properties so that downstream tools can reason about the linkage without reparsing the binary.

| Property                            | Value type     | What it captures                                                                            |
| ----------------------------------- | -------------- | ------------------------------------------------------------------------------------------- |
| `internal:symtab_symbols`           | delimited list | The symbol table symbols.                                                                   |
| `internal:dynamic_symbols`          | delimited list | The dynamic symbols.                                                                        |
| `internal:exported_symtab_symbols`  | delimited list | The exported symbol table symbols.                                                          |
| `internal:exported_dynamic_symbols` | delimited list | The exported dynamic symbols.                                                               |
| `internal:imports`                  | delimited list | The imported symbols, which indicates external dependency on platform or library functions. |
| `internal:exports`                  | delimited list | The exported symbols.                                                                       |
| `internal:export_functions`         | delimited list | The exported functions.                                                                     |
| `internal:symbol_version`           | single value   | The symbol version record for a symbol.                                                     |
| `internal:symbols_version`          | single value   | The aggregate symbol version information.                                                   |
| `internal:libPath`                  | single value   | The library path recorded for the binary.                                                   |
| `internal:hash_path`                | single value   | The path used for the binary hash lookup.                                                   |
| `internal:serviceable`              | boolean        | Whether the binary is considered serviceable.                                               |

## Dalvik behavioural properties

When deep mode is enabled, blint disassembles the dex methods using its Dalvik disassembler and runs a behavioural review over the decoded instructions. The review resolves the constant pool so that invoke targets, field accesses, and string constants appear as readable descriptors, then matches them against a set of behavioural rules. The findings are attached to the dex component that produced them.

There are two related properties. The summary property lists the triggered rule identifiers. Each triggered rule then gets its own detail property whose value is a compound string of the severity, the number of sites, and one example of the evidence.

| Property                  | Object        | Value type     | What it captures                                                          |
| ------------------------- | ------------- | -------------- | ------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal:behaviours`     | dex component | comma list     | The identifiers of the behavioural rules that triggered in this dex file. |
| `internal:behaviour:<ID>` | dex component | compound value | One entry per triggered rule. The value is `severity                      | count | sample`where severity is one of critical, high, medium, low, or info, count is the number of matched evidence entries recorded for the rule, and sample is one example of the matched descriptor or string. |

The behavioural rules that can appear as the `<ID>` suffix are listed below together with the behaviour they detect and the default severity.

| Rule identifier                | Severity | Behaviour                                                                                                                                                  |
| ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ANDROID_DYNAMIC_CODE_LOADING` | high     | The application loads code at runtime through a dex class loader.                                                                                          |
| `ANDROID_REFLECTION`           | medium   | The application resolves classes or methods through Java reflection.                                                                                       |
| `ANDROID_NATIVE_EXEC`          | high     | The application executes native commands or loads native libraries.                                                                                        |
| `ANDROID_WEAK_CRYPTO`          | high     | The application references a weak or broken cryptographic primitive such as DES, RC4, MD5, SHA-1, or the insecure ECB cipher mode.                         |
| `ANDROID_CLEARTEXT_TRAFFIC`    | medium   | The application references cleartext http endpoints.                                                                                                       |
| `ANDROID_WEBVIEW_UNSAFE`       | medium   | The application configures a WebView with unsafe settings such as JavaScript or file access.                                                               |
| `ANDROID_RAW_SQL`              | low      | The application executes raw SQL that may be injectable.                                                                                                   |
| `ANDROID_DEVICE_IDENTIFIERS`   | medium   | The application reads persistent device identifiers.                                                                                                       |
| `ANDROID_SMS_ACCESS`           | high     | The application sends or reads SMS messages.                                                                                                               |
| `ANDROID_INSTALLED_APPS_ENUM`  | low      | The application enumerates other installed applications.                                                                                                   |
| `ANDROID_ROOT_DETECTION`       | info     | The application probes for root or superuser binaries.                                                                                                     |
| `ANDROID_REMOTE_AI_SERVICE`    | medium   | The application calls a remote AI or LLM inference SDK or endpoint such as OpenAI, Anthropic, Gemini, or Bedrock.                                          |
| `ANDROID_ON_DEVICE_AI`         | info     | The application runs on-device inference through a framework such as TensorFlow Lite, ML Kit, ONNX Runtime, or PyTorch, or bundles a local model artifact. |
| `ANDROID_TRACKER_SDK`          | low      | The application embeds an analytics, crash reporting, or attribution tracker SDK.                                                                          |
| `ANDROID_AD_NETWORK`           | low      | The application embeds an advertising or adware SDK.                                                                                                       |

These rules are defined in the annotation file `blint/data/annotations/review_methods_android.yml` and keyed by the `dexbinary` exe type. They are loaded and matched by the same rule loader and pattern review engine that blint uses for native binary reviews, so the rule set can be extended by editing that file or by supplying a custom rules directory.

atom-tools reads these properties back from the BOM, aggregates the counts for the same rule across all dex files, and presents them as static behaviours alongside the reachability findings from atom. The behaviours are a static signal, so they describe what the code can do rather than what was proven reachable.

## Service properties

Services represent the remote endpoints and third party SDKs that the application talks to. blint produces services statically by matching dex class names against its bundled service and tracker catalogs. atom-tools produces services from reachability by reading the chen tags on the flows of a reachable slice. The two sets are merged by service reference, so a service that is both bundled and reachable carries the static detection and the reachability evidence together.

Each service uses a bom reference of the form `service:<Name>`. The `x-trust-boundary` field is set to indicate whether the service crosses a trust boundary, and the `data` array records the observed data flow direction and classification.

| Property or field         | Object             | Value type   | Producer   | What it captures                                                                                                                                                                                                                                                                |
| ------------------------- | ------------------ | ------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal:detection`      | service            | single value | blint      | The detection method. The value `static` indicates presence based detection from class names rather than proven reachability.                                                                                                                                                   |
| `internal:serviceKind`    | service            | single value | blint      | Whether the entry is a `service` or a `tracker`, taken from which catalog matched.                                                                                                                                                                                              |
| `internal:reachableFlows` | service            | number like  | atom-tools | The number of reachable flows that attribute traffic to this service.                                                                                                                                                                                                           |
| `internal:onDeviceAi`     | service            | boolean      | atom-tools | Set to true when the service represents on device inference rather than a remote call.                                                                                                                                                                                          |
| `data.flow`               | service data entry | enum string  | atom-tools | The data flow direction relative to the service. The value is `inbound` when the application sends to a remote service, `outbound` when a remote service sends to the device, `bi-directional` when both occur, and `unknown` for static detections that carry no reachability. |
| `x-trust-boundary`        | service            | boolean      | both       | Whether the service crosses a trust boundary. On device services do not cross a trust boundary, so this is false for them.                                                                                                                                                      |

The chen tag namespaces that drive the atom-tools service and tracker attribution are summarized here for context, since they are the upstream source of the service classifications even though they are not written directly into the BOM as properties. The personally identifiable information family uses tags such as `pii`, `pii-email`, `pii-device-id`, and `pii-national-id`. The regulated data families use `pci-dss` with the `pci-card-*` detail tags, `phi-medical`, and the regional regimes `gdpr`, `ccpa`, and `hipaa`. The financial family uses `finance-iban`, `finance-bank-account`, and `finance-crypto-wallet`. Secrets use `secret` with detail tags such as `secret-aws-access-key` and `secret-jwt`. Network direction uses `service-egress`, `service-ingress`, and `on-device-ai`. Third party SDKs use `tracker` with a category.

## The Dalvik callgraph sidecar

When disassembly is enabled, blint writes a callgraph next to the BOM rather than inside it, because a full callgraph is large. The file is named `<bom-stem>-<app>.dex-callgraph.json` and uses the same node and edge shape as the native binary callgraph that blint produces for ELF, PE, and Mach-O. Each node carries the method index, the resolved descriptor, and a flag that records whether the method has a body in the analyzed dex. Each edge is a caller to callee pair derived from the invoke instructions. The callgraph can be loaded by the blint callgraph tooling and exported to DOT or GraphML. atom-tools records the path to this sidecar in the report it writes so that the callgraph can be located alongside the other artifacts.

## Using these properties

The application metadata properties support manifest review without a second decode of the apk. A policy can read `internal:minSdkVersion` to decide whether platform hardening can be assumed, and `internal.appPermissions` to flag dangerous permission combinations.

The behavioural properties support static triage. A high severity behaviour such as `ANDROID_NATIVE_EXEC` or `ANDROID_DYNAMIC_CODE_LOADING` is a strong candidate for review, and the compound value gives an example call site so that a reviewer can start from concrete evidence. Because the behaviours are static, they are best used together with the reachability findings from atom, where a behaviour that is also reachable is higher confidence than one that is only present.

The service properties support data flow and third party review. The combination of `internal:detection` set to static and a nonzero `internal:reachableFlows` distinguishes an SDK that is merely bundled from one that the application actually uses, and the `data.flow` direction supports egress and ingress analysis.

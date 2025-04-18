# sbom-conformance

A tool to check the conformance of SBOMs to specifications. A checker for the NTIA Minimum Elements Specification is provided with the library.

> [!NOTE]  
> This library also contains specification checkers for SPDX requirements and the Google Style Guide, but these are not ready for use.

## How to use

sbom-conformance is a library and a CLI.

### Interactive

```
git clone git@github.com:google/sbom-conformance.git

cd sbom-conformance && go run main.go -specs eo -sbom testdata/sboms/simple.json
```

Run `go run main.go -h` to see the supported options.

### Programmatic

#### Initialization

The `BaseChecker` does the analysis of SBOMs. The following code creates a base checker, runs it, and generates the results.

```go
import (
	"github.com/google/sbom-conformance/pkg/checkers/base"
)

checker := base.NewChecker(base.WithGoogleChecker(),
                           base.WithEOChecker(),
                           base.WithSPDXChecker())

checker.RunChecks()

results := checker.Results()

```

You can choose any of the supported specs.

#### Accessing the Results

Text Summary:

```go
results.TextSummary
```

Structured summary of the SBOM and the conformance checks:

```go
results.Summary
```

Results of the top-level conformance checks:

```go
results.TopLevelChecks
```

There are two ways to get the results of the package-level conformance checks.

Get conformance checks per-package:

```go
results.PkgResults
```

Get the conformance checks directly, with statistics on the number of passed packages.

```go
results.PackageLevelChecks
```

## Supported Specifications

> [!IMPORTANT]  
> The only currently supported specification is the NTIA Minimum Elements.

### NTIA Minimum Elements

name: `EO`

A PDF of the specification can be found in https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf. The checker in this library verifies the minimum required "Data Fields", but not the minimum required "Automation Support" or the minimum required "Practices and Processes".

#### Author

This refers to the "Author of SBOM Data" data field in the NTIA specification. It is a top-level check that passes if the [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field) field contains at least one entry.

#### Timestamp

This refers to the "Timestamp" data field in the NTIA specification. It is a top-level check that passes if the [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field) field is present and non-empty.

#### Relationships

This refers to the "Dependency Relationship" data field in the NTIA specification. It is a top-level check that passes if every package is a member of some [Relationship](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/). The check does not require a specific `relationshipType`. Finally, the check will fail if both sides of the relationship are the same.

In the case that a package has no relationships, `NONE` can be used for `spdxElementId` or for `relatedSpdxElement`, and the check will pass for the package.

This is one interpretation of the NTIA specification. It differs from the SPDX intepretation ([defined here](https://spdx.github.io/spdx-spec/v2.3/how-to-use/#k2-satisfying-ntia-minimum-elements-for-an-sbom-using-spdx)), possibly because this library's intepretation does not factor in documents such as [Framing Software Component Transparency: Establishing a Common Software Bill of Material (SBOM)](https://www.ntia.gov/files/ntia/publications/framingsbom_20191112.pdf).

TODO: the `NOASSERTION` behavior should be made consistent with the other checks.

#### Name

This refers to the "Component Name" data field in the NTIA specification. It is a package-level check that passes if the [Name](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field) field is present and non-empty.

#### Version

This refers to the "Version of the Component" data field in the NTIA specification. It is a package-level check that passes if the [Version](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field) field is present, non-empty, and not `NOASSERTION`.

TODO: the `NOASSERTION` behavior should either be made configurable, or consistent with Supplier.

#### Supplier

This refers to the "Supplier Name" data field in the NTIA specification. It is a package-level check that passes if the [Package Supplier](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field) field is present and non-empty.

#### External References

This refers to the "Other Unique Identifiers" data field in the NTIA specification. It is a package-level check that passes if the [External References](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field) field is present and non-empty.

## Disclaimer

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

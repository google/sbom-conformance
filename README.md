# sbom-conformance

A tool to check the conformance of SBOMs to specifications. A checker for the NTIA Minimum Elements Specification and SPDX v2.3 requirements is provided with the library.

> [!NOTE]  
> This library also contains a checker for the Google Style Guide, but it is not yet ready for use.

> [!NOTE]  
> This library only supports SPDX v2.3 and JSON encoded SBOMs.

## How to use

sbom-conformance is a library and a CLI.

### Interactive

```
go install github.com/google/sbom-conformance@latest

sbom-conformance -specs eo -sbom <path to sbom>
```

Run `sbom-conformance -h` to see the supported options.

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
checker.SetSBOM(sbom)
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

### NTIA Minimum Elements

name: `EO`

A PDF of the specification can be found in https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf. The checker in this library verifies the minimum required "Data Fields", but not the minimum required "Automation Support" or the minimum required "Practices and Processes".

This checker considers `NOASSERTION` to be invalid for the Version, Supplier, and Relationships checks.

#### Author

This refers to the "Author of SBOM Data" data field in the NTIA specification. It is a top-level check that passes if the [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field) field contains at least one entry.

#### Timestamp

This refers to the "Timestamp" data field in the NTIA specification. It is a top-level check that passes if the [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field) field is present and non-empty.

#### Relationships

This refers to the "Dependency Relationship" data field in the NTIA specification. It is a top-level check that passes if, for every package, there exists a [relationship](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) where the package is either `spdxElementId` or `relatedSpdxElement` and where the other side of the relationship is not `NOASSERTION` or the package itself.

Note that the `relationshipType` is not considered. In the case that a package has no relationships, `NONE` can be used for `spdxElementId` or for `relatedSpdxElement`, and the check will pass for the package.

This is one interpretation of the NTIA specification. It differs from the SPDX intepretation ([defined here](https://spdx.github.io/spdx-spec/v2.3/how-to-use/#k2-satisfying-ntia-minimum-elements-for-an-sbom-using-spdx)), possibly because this library's intepretation does not factor in documents such as [Framing Software Component Transparency: Establishing a Common Software Bill of Material (SBOM)](https://www.ntia.gov/files/ntia/publications/framingsbom_20191112.pdf).

#### Name

This refers to the "Component Name" data field in the NTIA specification. It is a package-level check that passes if the [Name](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field) field is present and non-empty.

#### Version

This refers to the "Version of the Component" data field in the NTIA specification. It is a package-level check that passes if all of the following are true for the [Version](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field) field:
- it is present
- it is not empty
- it is not `NOASSERTION`

#### Supplier

This refers to the "Supplier Name" data field in the NTIA specification. It is a package-level check that passes if all of the following are true for the [Package Supplier](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field) field:
- it is present
- it is not empty
- it is not `NOASSERTION`

#### External References

This refers to the "Other Unique Identifiers" data field in the NTIA specification. It is a package-level check that passes if the [External References](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field) field is present and non-empty.

### SPDX 2.3

name: `SPDX`

The SPDX 2.3 specification (https://spdx.github.io/spdx-spec/v2.3/) requires that some fields are present and/or meet certain syntactic constraints.

#### Document Name

This is a top-level check that passes if the [Document Name](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name-field) field is present and not empty.

#### Document Namespace

This is a top-level check that passes if the [Document Namespace](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field) field is present and is a RFC 3986 URL with a scheme and without `#` characters.

#### Document SPDXID

This is a top-level check that passes if the [Document SPDX Identifier](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field) field is `SPDXRef-DOCUMENT`.

#### Creator

This is a top-level check that passes if the [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field) contains one or more entries and each entry is formatted correctly. The last parenthesis group in the creator is interpreted as the email.

#### Created

This is a top-level check that passes if the [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field) field is present and conforms to `YYYY-MM-DDThh:mm:ssZ`.

#### Other License Information

This is a top-level check that passes if, for each entry in the [Other Licensing Information ](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/) section, all of the following are true:
- the [License Identifier](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#101-license-identifier-field) field is present and conforms to `LicenseRef-<idstring>` where `idstring` only contains letters, numbers, `.`, and/or `-`
- the [License Identifier](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#101-license-identifier-field) field is unique among all entries
- the [Extracted Text Field](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#102-extracted-text-field) is present and not empty

The licenses are not checked against the [SPDX license list](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-list/).

#### Data License

This is a top-level check that passes if the [Data License](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field) field is `CC0-1.0`.

#### Package Name

This is a package-level check that passes if the [Name](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field) field is present and non-empty.

#### Package SPDXID

This is a package-level check that passes if the [Package SPDX Identifier](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field) field is present and conforms to `SPDXRef-<idstring>` where `idstring` only contains letters, numbers, `.`, and/or `-`.

#### Package SPDXID Uniqueness

This is a top-level check that passes if the [Package SPDX Identifier](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field) field is unique among all packages.

#### Download Location

This is a package-level check that passes if the [Package Download Location](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field) field is present and not empty.

#### Files Analyzed

This is a package-level check that passes if either of the following are true:
- the [Package Verification Code](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field) field is missing
- the [Package Verification Code](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field) field is present and the [Files Analyzed](https://spdx.github.io/spdx-spec/v2.3/package-information/#78-files-analyzed-field) field is `true`

### Google Style Guide

name: `google`

The Google SBOM Style Guide is similar to the SPDX requirements with a few additional restriction.

#### Document Name

This is a top-level check that passes if the [Document Name](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#64-document-name-field) field is present and not empty.

#### Document Name

This is a top-level check that passes if the [Document Namespace](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field) field is present and conforms to `https://spdx.google/<uuid>`.

#### Data License

This is a top-level check that passes if the [Data License](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field) field is `CC0-1.0`.

#### Document SPDXID

This is a top-level check that passes if the [Document SPDX Identifier](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field) field is `SPDXRef-DOCUMENT`.

#### Creator

This is a top-level check that passes if the [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field) contains an "`Organization: Google LLC` entry, contains a `Tool` entry, and does not contain a `Person` entry.

#### Created

This is a top-level check that passes if the [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field) field is present and conforms to `YYYY-MM-DDThh:mm:ssZ`.

#### Other License Information

This is a top-level check that passes if, for each entry in the [Other Licensing Information ](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/) section, all of the following are true:
- the [License Identifier](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#101-license-identifier-field) field is present and conforms to `LicenseRef-<idstring>` where `idstring` only contains letters, numbers, `.`, and/or `-`
- the [License Identifier](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#101-license-identifier-field) field is unique among all entries
- the [Extracted Text Field](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#102-extracted-text-field) is present and not empty

## Disclaimer

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

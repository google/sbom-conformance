# sbom-conformance

A tool to check the conformance of SBOMs compared to Googles internal spec, the EO requirements and the SPDX requirements.

> [!IMPORTANT] This library is being developed. It's not recommended to use it yet.

## How to use

sbom-conformance is a library. See below how to use it.

### Create a `BaseChecker`

The `BaseChecker` does the analysis of SBOMs. To create one with the Google Internal specs, the EO specs and the SPDX specs, do the following:

```go
import (
	"github.com/google/sbom-conformance/pkg/checkers/base"
)

checker := base.NewChecker(base.WithGoogleChecker(),
                           base.WithEOChecker(),
                           base.WithSPDXChecker())


```

You can choose any of the supported specs.

### Run checks and view results

With a `BaseChecker`, we can now run all top-level checks and package-level checks:

```go

checker.RunChecks()

```

After that, you can get information about the SBOM and its conformance.

#### Results

##### Create the results

```go
results := checker.Results()
```

##### Text summary

Get a text summary of the SBOM and the conformance checks.

```go
results.TextSummary
```

##### Structured summary

Get a structured summary of the SBOM and the conformance checks.

```go
results.Summary
```

##### Get package results

Gets structured results for the packages from the checks.

```go
results.PkgResults
```

##### Get error results

Gets the output of the conformance checks sorted by issues found.

```go
results.PkgResults
```

##### ChecksInRun

Gets a summary of the checks that were included in the run.

```go
results.ChecksInRun
```

## main.go

sbom-conformance is currently mainly intended to be used as a library. We have a `main.go` that is in WIP. It may not support all features in sbom-conformance, but if you wish to use sbom-conformance as a standalone CLI tool, we accept pull requests for our `mail.go` file.

## Supported Specifications

> [!IMPORTANT] This documentation is being developed and is not complete.

### NTIA Minimum Elements

name: `EO`

A PDF of the specification can be found in https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf.

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

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

# sbom-conformance

A tool to check the conformance of SBOMs compared to Googles internal spec, the EO requirements and the SPDX requirements.

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

## Disclaimer
This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).

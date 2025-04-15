// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

type SpecSummary struct {
	// true if len(TotalChecks) == len(PassedChecks)
	Conformant bool `json:"conformant"`

	PassedChecks int `json:"passedChecks"`
	TotalChecks  int `json:"totalChecks"`
}

type TopLevelCheckResult struct {
	Name   string   `json:"name"`
	Passed bool     `json:"passed"`
	Specs  []string `json:"specs"`
}

type PackageLevelCheckResult struct {
	Name              string   `json:"name"`
	FailedPkgsPercent float32  `json:"failedPkgsPercent,omitempty"`
	Specs             []string `json:"specs"`
}

// Output is the type we convert to json when we output the results.
type Output struct {
	// TextSummary is a text summary of the conformance checks
	TextSummary string `json:"textSummary"`

	// Summary is a structured summary of the conformance checks
	Summary *Summary `json:"summary"`

	// TopLevelChecks is a list of the top-level checks that were run along with
	// the specifications they are a part of and whether they passed or not.
	TopLevelChecks []*TopLevelCheckResult `json:"topLevelChecks"`

	// PackageLevelChecks a list of the package-checks that were run along with
	// the specifications they are a part of and the number of packages they passed
	// for.
	PackageLevelChecks []*PackageLevelCheckResult `json:"packageLevelChecks"`

	// PkgResults is a list of the packages in the SBOM, along with the conformance
	// checks that each package failed.
	PkgResults []*PkgResult `json:"pkgResults,omitempty"`

	// ErrsAndPacks is a map of failed conformance checks to the names of the
	// packages that failed them.
	// TODO - does this need to exist?
	ErrsAndPacks map[string][]string `json:"errsAndPacks,omitempty"`
}

type Summary struct {
	SpecSummaries      map[string]*SpecSummary `json:"specSummaries"`
	TotalSBOMPackages  int                     `json:"totalSbomPackages"`
	FailedSBOMPackages int                     `json:"failedSbomPackages"`
}

func OutputFromInput(pkgResults []*PkgResult,
	errsAndPacks map[string][]string,
	totalSBOMPkgs, failedSBOMackages int,
	topLevelChecks []*TopLevelCheckResult,
	packageLevelChecks []*PackageLevelCheckResult,
) *Output {
	return &Output{
		PkgResults:         pkgResults,
		ErrsAndPacks:       errsAndPacks,
		TopLevelChecks:     topLevelChecks,
		PackageLevelChecks: packageLevelChecks,
	}
}

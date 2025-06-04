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

package util

import (
	"fmt"
	"slices"
	"strings"

	types "github.com/google/sbom-conformance/pkg/checkers/types"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type DeduplicatedIssue struct {
	ErrorType              string
	ErrorMessage           string
	CheckName              string
	NonConformantWithSpecs []string
}

// Removes duplicate issues and tags them with the spec that found them.
func DeduplicateIssues(issues []*types.NonConformantField) []*DeduplicatedIssue {
	// Create the list for the deduplicated issues
	deduplicatedIssues := make([]*DeduplicatedIssue, 0)

	// Go through list of duplicate issues
	for _, issue := range issues {
		// Skip if this issue already is in the list of deduplicated issues
		if alreadyDeduplicated(issue, deduplicatedIssues) {
			continue
		}

		// Get all the specs that have flagged this as an issue
		reportedBySpecs := issueIsReportedBySpecs(issue, issues)

		// Merge the issues into one
		// This issue will have a list of the specs that flagged it
		deduplicatedIssue := &DeduplicatedIssue{
			ErrorType:              issue.Error.ErrorType,
			ErrorMessage:           issue.Error.ErrorMsg,
			NonConformantWithSpecs: reportedBySpecs,
			CheckName:              issue.CheckName,
		}
		deduplicatedIssues = append(deduplicatedIssues, deduplicatedIssue)
	}
	return deduplicatedIssues
}

func alreadyDeduplicated(
	issue *types.NonConformantField,
	deduplicatedIssues []*DeduplicatedIssue,
) bool {
	for _, iss := range deduplicatedIssues {
		if iss.ErrorMessage == issue.Error.ErrorMsg && iss.CheckName == issue.CheckName {
			return true
		}
	}
	return false
}

func issueIsReportedBySpecs(
	issue *types.NonConformantField,
	issues []*types.NonConformantField,
) []string {
	specs := make([]string, 0)
	for _, i := range issues {
		if i.Error.ErrorMsg == issue.Error.ErrorMsg {
			specs = append(specs, i.ReportedBySpec...)
		}
	}
	// Sort the specs
	slices.Sort(specs)
	// Remove duplicates
	specs = slices.Compact(specs)
	return specs
}

func IsValidString(v string) bool {
	if v == "" {
		return false
	}
	if strings.ToLower(v) == "noassertion" {
		return false
	}
	if strings.ToLower(v) == "none" {
		return false
	}
	return true
}

func getPackageName(pack *v23.Package) string {
	return pack.PackageName
}

func getPackageID(pack *v23.Package) string {
	return string(pack.PackageSPDXIdentifier)
}

func RunPkgLevelChecks(
	doc *v23.Document,
	checks []*types.PackageLevelCheck,
	specName string,
) []*types.PkgResult {
	pkgResults := make([]*types.PkgResult, 0)

	for _, pack := range doc.Packages {
		packageName := getPackageName(pack)
		packageID := getPackageID(pack)

		// Run checks on package
		issues := make([]*types.NonConformantField, 0)
		for _, c := range checks {
			packIssues := c.Impl(pack, specName, c.Name)
			issues = append(issues, packIssues...)
		}

		// Here we also create a PkgResult if there are no
		// issues in the package. That may not be good in
		// all future cases, however, for now it poses no
		// problems.
		pkgResult := &types.PkgResult{
			Package: &types.Package{
				Name:   packageName,
				SpdxID: packageID,
			},
			Errors: issues,
		}
		pkgResults = append(pkgResults, pkgResult)
	}
	return pkgResults
}

// StringBuilder augments strings.Builder to allow for easier formatting and
// application of prefixes and suffixes.
type StringBuilder struct {
	s      *strings.Builder
	prefix string
	suffix string
}

// StringBuilderWithPrefix returns a StringBuilder that will send all writes to
// initialStringBuilder, with the prefix and suffix applied before and after
// each write.
func StringBuilderWithPrefixAndSuffix(
	initialStringBuilder *strings.Builder,
	prefix string,
	suffix string,
) *StringBuilder {
	return &StringBuilder{s: initialStringBuilder, prefix: prefix, suffix: suffix}
}

// Writef formats according to a format specifier and writes to the StringBuilder,
// applying the prefix and suffix.
func (sb *StringBuilder) Writef(format string, a ...any) {
	sb.s.WriteString(sb.prefix)
	fmt.Fprintf(sb.s, format, a...)
	sb.s.WriteString(sb.suffix)
}

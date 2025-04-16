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

package base

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
)

func TestDeduplicatePackageResults(t *testing.T) {
	t.Parallel()
	licenseName := "Other License"
	spec := "Google"
	packageResults := []*types.PkgResult{
		{
			Package: &types.Package{
				Name: "pkg1",
			},
			Errors: []*types.NonConformantField{
				types.OtherLicenseError(
					licenseName,
					spec,
					"License Cross Reference is required.",
				),
				types.OtherLicenseError(
					licenseName,
					spec,
					"License Cross Reference is required.",
				),
			},
		},
	}
	deduplicated := deduplicatePackageResults(packageResults)
	if len(deduplicated) != 1 {
		t.Fatalf("There should only be 1 deduplicated pkgResult. Found %d", len(deduplicated))
	}
	if len(deduplicated[0].Errors) != 1 {
		t.Fatalf("There should only be 1 error. Found %d", len(deduplicated[0].Errors))
	}
	if len(deduplicated[0].Errors[0].ReportedBySpec) != 1 {
		t.Fatalf(
			"There should only be 1 spec. Found %d",
			len(deduplicated[0].Errors[0].ReportedBySpec),
		)
	}
	if deduplicated[0].Errors[0].ReportedBySpec[0] != "Google" {
		t.Errorf(
			"The spec should be 'Google' but is '%s'",
			deduplicated[0].Errors[0].ReportedBySpec[0],
		)
	}
}

func simpleError(
	reportedBySpec []string,
	errorType, errorMsg, checkName string,
) *types.NonConformantField {
	return &types.NonConformantField{
		ReportedBySpec: reportedBySpec,
		Error: &types.FieldError{
			ErrorType: errorType,
			ErrorMsg:  errorMsg,
		},
		CheckName: checkName,
	}
}

func TestMergePkgResults(t *testing.T) {
	t.Parallel()
	type input struct {
		pkgs     []*types.PkgResult
		expected []*types.PkgResult
	}

	inputs := []input{
		{
			pkgs: []*types.PkgResult{
				{
					Package: &types.Package{
						Name: "packagename1",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec1"}, "type1", "msg1", "checkName1"),
						simpleError([]string{"spec1"}, "type2", "msg2", "checkName2"),
						simpleError([]string{"spec1"}, "type3", "msg3", "checkName3"),
					},
				},
				{
					Package: &types.Package{
						Name: "packagename1",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec2"}, "type11", "msg11", "checkName111"),
						simpleError([]string{"spec2"}, "type22", "msg22", "checkName222"),
						simpleError([]string{"spec2"}, "type33", "msg33", "checkName333"),
						simpleError([]string{"spec2"}, "type44", "msg44", "checkName444"),
					},
				},
				{
					Package: &types.Package{
						Name: "packagename2",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec20"}, "type10", "msg10", "checkName1110"),
						simpleError([]string{"spec20"}, "type20", "msg20", "checkName2220"),
						simpleError([]string{"spec20"}, "type30", "msg30", "checkName3330"),
						simpleError([]string{"spec20"}, "type40", "msg40", "checkName4440"),
					},
				},
			},
			expected: []*types.PkgResult{
				{
					Package: &types.Package{
						Name: "packagename1",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec1"}, "type1", "msg1", "checkName1"),
						simpleError([]string{"spec1"}, "type2", "msg2", "checkName2"),
						simpleError([]string{"spec1"}, "type3", "msg3", "checkName3"),
						simpleError([]string{"spec2"}, "type11", "msg11", "checkName111"),
						simpleError([]string{"spec2"}, "type22", "msg22", "checkName222"),
						simpleError([]string{"spec2"}, "type33", "msg33", "checkName333"),
						simpleError([]string{"spec2"}, "type44", "msg44", "checkName444"),
					},
				},
				{
					Package: &types.Package{
						Name: "packagename2",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec20"}, "type10", "msg10", "checkName1110"),
						simpleError([]string{"spec20"}, "type20", "msg20", "checkName2220"),
						simpleError([]string{"spec20"}, "type30", "msg30", "checkName3330"),
						simpleError([]string{"spec20"}, "type40", "msg40", "checkName4440"),
					},
				},
			},
		},
	}
	for _, inp := range inputs {
		got := mergePkgResults(inp.pkgs)
		if len(got) != 2 {
			t.Errorf("We expected 2 PkgResults, but we got %d", len(got))
		}
		for i := range got {
			if !CompareTwoPkgResults(t, got[i], inp.expected[i]) {
				t.Errorf("got pkg %d is wrong", i)
			}
		}
	}
}

// This is a primitive utility to compare two pkgResults.
// Returns "false" if the two pkgResults are not identical.
// Only used for testing.
func CompareTwoPkgResults(t *testing.T, got, expected *types.PkgResult) bool {
	t.Helper()
	if got.Package.Name != expected.Package.Name && got.Package.SpdxID != expected.Package.SpdxID {
		t.Log("The two packages have different names")
		return false
	}
	if len(got.Errors) != len(expected.Errors) {
		t.Log("The two packages have a different number of errors")
		return false
	}
	for i := range got.Errors {
		pkg1ErrorNil := got.Errors[i].Error == nil
		pkg2ErrorNil := expected.Errors[i].Error == nil
		bothErrorAreNilOrNot := pkg1ErrorNil == pkg2ErrorNil
		if !bothErrorAreNilOrNot {
			t.Logf("error %d bothErrorAreNilOrNot: %t\n", i, bothErrorAreNilOrNot)
			return false
		}
		if got.Errors[i].Error.ErrorType != expected.Errors[i].Error.ErrorType {
			t.Logf("error %d Error.ErrorType is not identical\n", i)
			return false
		}
		if got.Errors[i].Error.ErrorMsg != expected.Errors[i].Error.ErrorMsg {
			t.Logf("error %d Error.ErrorMsg is not identical\n", i)
			return false
		}
		for j := range got.Errors[i].ReportedBySpec {
			if !strings.EqualFold(
				got.Errors[i].ReportedBySpec[j],
				expected.Errors[i].ReportedBySpec[j],
			) {
				t.Logf("error %d spec %d is not correct. got=%s and expected=%s\n",
					i, j, got.Errors[i].ReportedBySpec[j], expected.Errors[j].ReportedBySpec[j])
				return false
			}
		}
		if got.Errors[i].CheckName != expected.Errors[i].CheckName {
			t.Logf("error %d CheckName is not correct \n", i)
		}
	}
	return true
}

func TestPkgResultsForMultiplePackagesAndErrorsAndSpecs(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		specs    []func(*BaseChecker)
		expected []*types.PkgResult
	}{
		{
			name: "Packages with equal names but different SPDXIDs are not merged",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [
						{
							"name": "Foo",
							"SPDXID": "SPDXRef-foo-1",
							"versionInfo": "v1",
							"supplier": "Organization: foo",
							"externalRefs": [{
								"referenceCategory": "PACKAGE-MANAGER", 
								"referenceType": "purl",
								"referenceLocator": "pkg:foo"
							}]
						},
						{
							"name": "Foo",
							"SPDXID": "SPDXRef-foo-2",
							"versionInfo": "v1",
							"supplier": "Organization: foo",
							"externalRefs": [{
								"referenceCategory": "PACKAGE-MANAGER", 
								"referenceType": "purl",
								"referenceLocator": "pkg:foo"
							}]
						}
					]
				}`,
			specs: []func(*BaseChecker){WithEOChecker()},
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "Foo", SpdxID: "foo-1"},
					Errors:  []*types.NonConformantField{},
				},
				{
					Package: &types.Package{Name: "Foo", SpdxID: "foo-2"},
					Errors:  []*types.NonConformantField{},
				},
			},
		},
		{
			name: "Multiple package errors are surfaced",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [
						{
							"name": "Foo",
							"SPDXID": "SPDXRef-foo",
							"externalRefs": [{
								"referenceCategory": "PACKAGE-MANAGER", 
								"referenceType": "purl",
								"referenceLocator": "pkg:foo"
							}]
						}
					]
				}`,
			specs: []func(*BaseChecker){WithEOChecker()},
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{
					{
						Error: &types.FieldError{
							ErrorType: "missingField",
							ErrorMsg:  "The supplier field is missing",
						},
						CheckName:      "Check that the package has a supplier",
						ReportedBySpec: []string{"EO"},
					},
					{
						Error: &types.FieldError{
							ErrorType: "missingField",
							ErrorMsg:  "Has no PackageVersion field",
						},
						CheckName:      "Check that SBOM packages have a valid version",
						ReportedBySpec: []string{"EO"},
					},
				},
			}},
		},
		{
			name:  "Multiple specs are reported in package errors",
			specs: []func(*BaseChecker){WithEOChecker(), WithSPDXChecker()},
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "v1",
						"supplier": "Organization: foo",
						"downloadLocation": "foo.com",
						"filesAnalyzed": false,
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageName field",
					},
					CheckName:      "Check that SBOM packages have a name",
					ReportedBySpec: []string{"EO", "SPDX"},
				}},
			}},
		},
	}

	lessPkgResult := func(package1, package2 *types.PkgResult) bool {
		return package1.Package.SpdxID < package2.Package.SpdxID
	}
	lessFieldError := func(error1, error2 *types.NonConformantField) bool {
		// All errors with the same ErrorMsg should have the same ErrorType
		return error1.Error.ErrorMsg < error2.Error.ErrorMsg
	}
	lessReportedBySpec := func(s1, s2 string) bool { return s1 < s2 }
	opts := cmp.Options{
		cmpopts.SortSlices(lessPkgResult),
		cmpopts.SortSlices(lessFieldError),
		cmpopts.SortSlices(lessReportedBySpec),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(tt.specs...)
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			checker, err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(tt.expected, checker.Results().PkgResults, opts); diff != "" {
				t.Errorf("Encountered checker.Results() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// Note: these parse failures should either be folded into the quality evaluation,
// or they should return more specific errors.
func TestParseFailure(t *testing.T) {
	tests := []struct {
		name string
		sbom string
	}{
		{
			name: "Supplier with invalid format causes parse failure",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo",
					"versionInfo": "v1",
					"supplier": "not an organization",
					"externalRefs": [{
						"referenceCategory": "PACKAGE-MANAGER", 
						"referenceType": "purl",
						"referenceLocator": "pkg:foo"
					}]
				}]
			}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithEOChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			_, err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err == nil {
				t.Fatalf("SetSBOM did not return an error")
			}
		})
	}
}

func TestEOTopLevelChecks(t *testing.T) {
	// there's a tradeoff between making these test cases more specific (and less
	// verbose) and adding additional logic to the test case. As written, they
	// avoid the logic and are less specific.
	tests := []struct {
		name     string
		sbom     string
		expected []*types.TopLevelCheckResult
	}{
		{
			name: "Missing fields cause author and timestamp checks to fail",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo"
				}]
			}`,
			expected: []*types.TopLevelCheckResult{
				{
					Name:   "Check that the SBOM has an SPDX version",
					Passed: true,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOM has at least one creator",
					Passed: false,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOM has a timestamp",
					Passed: false,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOMs packages are correctly formatted",
					Passed: true,
					Specs:  []string{"EO"},
				},
			},
		},
		{
			name: "Empty fields cause author and timestamp checks to fail",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": [],
					"created": ""
				},
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo"
				}]
			}`,
			expected: []*types.TopLevelCheckResult{
				{
					Name:   "Check that the SBOM has an SPDX version",
					Passed: true,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOM has at least one creator",
					Passed: false,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOM has a timestamp",
					Passed: false,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOMs packages are correctly formatted",
					Passed: true,
					Specs:  []string{"EO"},
				},
			},
		},
		{
			name: "Author and timestamp checks pass",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo"
				}]
			}`,
			expected: []*types.TopLevelCheckResult{
				{
					Name:   "Check that the SBOM has an SPDX version",
					Passed: true,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOM has at least one creator",
					Passed: true,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOM has a timestamp",
					Passed: true,
					Specs:  []string{"EO"},
				},
				{
					Name:   "Check that the SBOMs packages are correctly formatted",
					Passed: true,
					Specs:  []string{"EO"},
				},
			},
		},
	}

	lessTopLevelCheckResult := func(check1, check2 *types.TopLevelCheckResult) bool {
		return check1.Name < check2.Name
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithEOChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			checker, err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(
				tt.expected,
				checker.Results().TopLevelChecks,
				cmpopts.SortSlices(lessTopLevelCheckResult)); diff != "" {
				t.Errorf("Encountered checker.TopLevelResults() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// This intends to test the output.PackageLevelCheckResult API, not
// the correctness of any package level checks themselves. That is tested by
// TestEOPkgResults (and similar for the other specifications).
func TestPackageLevelChecks(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []*types.PackageLevelCheckResult
		specs    []func(*BaseChecker)
	}{
		{
			name: "1/2 packages fail all checks",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [
					{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "Organization: foo",
						"versionInfo": "v1",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					},
					{
						"name": "",
						"SPDXID": "SPDXRef-bar"
					}
 				]
			}`,
			specs: []func(*BaseChecker){WithEOChecker()},
			expected: []*types.PackageLevelCheckResult{
				{
					Name:              "Check that SBOM packages have a valid version",
					FailedPkgsPercent: 50,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have a name",
					FailedPkgsPercent: 50,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have external references",
					FailedPkgsPercent: 50,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that the package has a supplier",
					FailedPkgsPercent: 50,
					Specs:             []string{"EO"},
				},
			},
		},
		{
			name: "2/2 packages fail all checks",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [
					{
						"name": "",
						"SPDXID": "SPDXRef-foo"
					},
					{
						"name": "",
						"SPDXID": "SPDXRef-bar"
					}
 				]
			}`,
			specs: []func(*BaseChecker){WithEOChecker()},
			expected: []*types.PackageLevelCheckResult{
				{
					Name:              "Check that SBOM packages have a valid version",
					FailedPkgsPercent: 100,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have a name",
					FailedPkgsPercent: 100,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have external references",
					FailedPkgsPercent: 100,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that the package has a supplier",
					FailedPkgsPercent: 100,
					Specs:             []string{"EO"},
				},
			},
		},
		{
			name: "2/2 packages pass all checks",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [
					{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "Organization: foo",
						"versionInfo": "v1",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					},
					{
						"name": "Bar",
						"SPDXID": "SPDXRef-bar",
						"supplier": "Organization: foo",
						"versionInfo": "v1",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}
 				]
			}`,
			specs: []func(*BaseChecker){WithEOChecker()},
			expected: []*types.PackageLevelCheckResult{
				{
					Name:              "Check that SBOM packages have a valid version",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have a name",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have external references",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that the package has a supplier",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
			},
		},
		{
			name: "Multiple specs are reported",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [
					{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "Organization: foo",
						"filesAnalyzed": false,
						"downloadLocation": "foo.com",
						"versionInfo": "v1",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}
 				]
			}`,
			specs: []func(*BaseChecker){WithEOChecker(), WithSPDXChecker()},
			expected: []*types.PackageLevelCheckResult{
				{
					Name:              "Check that SBOM packages have a valid version",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages have a name",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO", "SPDX"},
				},
				{
					Name:              "Check that SBOM packages have external references",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that the package has a supplier",
					FailedPkgsPercent: 0,
					Specs:             []string{"EO"},
				},
				{
					Name:              "Check that SBOM packages' ID is correctly formatted",
					FailedPkgsPercent: 0,
					Specs:             []string{"SPDX"},
				},
				{
					Name:              "Check that SBOM packages' verification code is correctly formatted",
					FailedPkgsPercent: 0,
					Specs:             []string{"SPDX"},
				},
				{
					Name:              "Check that SBOM packages' download location is correctly formatted",
					FailedPkgsPercent: 0,
					Specs:             []string{"SPDX"},
				},
			},
		},
	}

	lessPackageLeveResult := func(check1, check2 *types.PackageLevelCheckResult) bool {
		return check1.Name < check2.Name
	}
	lessReportedBySpec := func(s1, s2 string) bool { return s1 < s2 }
	opts := cmp.Options{
		cmpopts.SortSlices(lessPackageLeveResult),
		cmpopts.SortSlices(lessReportedBySpec),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(tt.specs...)
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			checker, err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(
				tt.expected,
				checker.Results().PackageLevelChecks,
				opts); diff != "" {
				t.Errorf("Encountered checker.TopLevelResults() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEOPkgResults(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []*types.PkgResult
	}{
		{
			name: "No package failures",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "v1",
						"supplier": "Organization: foo",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors:  []*types.NonConformantField{},
			}},
		},
		{
			name: "Missing supplier fails check",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo",
					"versionInfo": "v1",
					"externalRefs": [{
						"referenceCategory": "PACKAGE-MANAGER", 
						"referenceType": "purl",
						"referenceLocator": "pkg:foo"
					}]
				}]
			}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "The supplier field is missing",
					},
					CheckName:      "Check that the package has a supplier",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Supplier is NOASSERTION passes check",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo",
					"versionInfo": "v1",
					"supplier": "Organization: foo",
					"externalRefs": [{
						"referenceCategory": "PACKAGE-MANAGER", 
						"referenceType": "purl",
						"referenceLocator": "pkg:foo"
					}]
				}]
			}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors:  []*types.NonConformantField{},
			}},
		},
		{
			name: "Missing package version fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "Organization: foo",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageVersion field",
					},
					CheckName:      "Check that SBOM packages have a valid version",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Empty package version string fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "",
						"supplier": "Organization: foo",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageVersion field",
					},
					CheckName:      "Check that SBOM packages have a valid version",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Package version is NOASSERTION fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "NOASSERTION",
						"supplier": "Organization: foo",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageVersion field",
					},
					CheckName:      "Check that SBOM packages have a valid version",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Missing package name fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "v1",
						"supplier": "Organization: foo",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageName field",
					},
					CheckName:      "Check that SBOM packages have a name",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Empty package name string fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "",
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "v1",
						"supplier": "Organization: foo",
						"externalRefs": [{
							"referenceCategory": "PACKAGE-MANAGER", 
							"referenceType": "purl",
							"referenceLocator": "pkg:foo"
						}]
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageName field",
					},
					CheckName:      "Check that SBOM packages have a name",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Missing package external references fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "v1",
						"supplier": "Organization: foo"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageExternalReferences field",
					},
					CheckName:      "Check that SBOM packages have external references",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
		{
			name: "Empty package external references fails check",
			sbom: `{
					"spdxVersion": "SPDX-2.3",
					"name": "SimpleSBOM",
					"packages": [{
						"name": "Foo",
						"SPDXID": "SPDXRef-foo",
						"versionInfo": "v1",
						"supplier": "Organization: foo",
						"externalRefs": []
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "Foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageExternalReferences field",
					},
					CheckName:      "Check that SBOM packages have external references",
					ReportedBySpec: []string{"EO"},
				}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithEOChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			checker, err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(tt.expected, checker.Results().PkgResults); diff != "" {
				t.Errorf("Encountered checker.Results() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// e2e test for the EO checker.
//
//nolint:all
func TestEOChecker(t *testing.T) {
	sbom := "simple.json"
	checker, err := NewChecker(WithEOChecker())
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sboms", sbom))
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()
	results := checker.Results()

	if results.Summary.TotalSBOMPackages != 4 {
		t.Errorf("There should be 4 TotalSBOMPackages but the results only had %d\n",
			results.Summary.TotalSBOMPackages)
	}
	if results.Summary.FailedSBOMPackages != 4 {
		t.Errorf("There should be 4 FailedSBOMPackages but the results only had %d\n",
			results.Summary.FailedSBOMPackages)
	}
	if len(results.Summary.SpecSummaries) != 1 {
		t.Errorf("There should be a single specsummary for 'EO' but there were %d\n",
			len(results.Summary.SpecSummaries))
	}
	if results.Summary.SpecSummaries["EO"].Conformant != false {
		t.Errorf("The 'EO' spec summary should be Conformant=true but was Conformant=%t\n",
			results.Summary.SpecSummaries["EO"].Conformant)
	}
	if results.Summary.SpecSummaries["EO"].PassedChecks != 5 {
		t.Errorf("The 'EO' spec summary should be PassedChecks=5 but was PassedChecks=%d\n",
			results.Summary.SpecSummaries["EO"].PassedChecks)
	}
	if len(results.PkgResults) != results.Summary.FailedSBOMPackages {
		t.Errorf(
			"len(results.PkgResults) should be the same as results.Summary.FailedSBOMPackages but was %d\n",
			len(results.PkgResults),
		)
	}

	// First package findings
	packageName := results.PkgResults[0].Package.Name
	if packageName != "Some Package" {
		t.Errorf("The first package should be named 'Some Package' but was named '%s'", packageName)
	}
	if len(results.PkgResults[0].Errors) != 2 {
		t.Error("There should only be two errors")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorMsg != "The supplier field is missing" {
		t.Errorf("Should be 'The supplier field is missing' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[0].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}
	if results.PkgResults[0].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[1].Error.ErrorMsg != "Has no PackageExternalReferences field" {
		t.Errorf("Should be 'Has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[0].Errors[1].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Second package findings
	packageName = results.PkgResults[1].Package.Name
	if results.PkgResults[1].Package.Name != "" {
		t.Errorf("The second package should be named '' but was named %s", packageName)
	}
	if len(results.PkgResults[1].Errors) != 3 {
		t.Error("There should be three errors")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorMsg != "Has no PackageName field" {
		t.Errorf("Should be 'Has no PackageName field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorMsg != "The supplier field is missing" {
		t.Errorf("Should be 'The supplier field is missing' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[1].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}
	if results.PkgResults[1].Errors[2].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[2].Error.ErrorMsg != "Has no PackageExternalReferences field" {
		t.Errorf("Should be 'Has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[2].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Third package findings
	packageName = results.PkgResults[2].Package.Name
	if results.PkgResults[2].Package.Name != "another package" {
		t.Errorf(
			"The third package should be named 'another package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 2 {
		t.Error("There should be two errors")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "The supplier field is missing" {
		t.Errorf("Should be 'The supplier field is missing' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}
	if results.PkgResults[2].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[1].Error.ErrorMsg != "Has no PackageExternalReferences field" {
		t.Errorf("Should be 'Has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[1].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Fourth package findings
	packageName = results.PkgResults[3].Package.Name
	if results.PkgResults[3].Package.Name != "last package" {
		t.Errorf(
			"The fourth package should be named 'last package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[3].Errors) != 1 {
		t.Error("There should be two errors")
	}
	if results.PkgResults[3].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[3].Errors[0].Error.ErrorMsg != "Has no PackageExternalReferences field" {
		t.Errorf("Should be 'Has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Check results.Errs.AndPacks
	if len(results.ErrsAndPacks) != 3 {
		t.Errorf(
			"The length of results.ErrsAndPacks should be 3 but is %d",
			len(results.ErrsAndPacks),
		)
	}
	expect := []string{
		"Some Package",
		"Package-1",
		"another package",
		"last package",
	}
	if !slices.Equal(results.ErrsAndPacks["Has no PackageExternalReferences field"], expect) {
		t.Errorf(
			"Expected %+v but got %+v",
			expect,
			results.ErrsAndPacks["Has no PackageExternalReferences field"],
		)
	}
	/*expect = []string{"Package-1"}
	if !slices.Equal(results.ErrsAndPacks["Has no PackageName field"], expect) {
		t.Error("Wrong")
	}*/
}

// e2e test for the Google checker.
//
//nolint:all
func TestGoogleChecker(t *testing.T) {
	sbom := "simple.json"
	checker, err := NewChecker(WithGoogleChecker())
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sboms", sbom))
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()
	results := checker.Results()

	if results.Summary.TotalSBOMPackages != 4 {
		t.Errorf("There should be 4 TotalSBOMPackages but the results only had %d\n",
			results.Summary.TotalSBOMPackages)
	}
	if results.Summary.FailedSBOMPackages != 3 {
		t.Errorf("There should be 3 FailedSBOMPackages but the results only had %d\n",
			results.Summary.FailedSBOMPackages)
	}
	if len(results.Summary.SpecSummaries) != 1 {
		t.Errorf("There should be a single specsummary for 'Google' but there were %d\n",
			len(results.Summary.SpecSummaries))
	}
	if results.Summary.SpecSummaries["Google"].Conformant != false {
		t.Errorf("The 'Google' spec summary should be Conformant=true but was Conformant=%t\n",
			results.Summary.SpecSummaries["Google"].Conformant)
	}
	if results.Summary.SpecSummaries["Google"].PassedChecks != 7 {
		t.Errorf("The 'Google' spec summary should be PassedChecks=7 but was PassedChecks=%d\n",
			results.Summary.SpecSummaries["Google"].PassedChecks)
	}
	if len(results.PkgResults) != 4 {
		t.Errorf("len(results.PkgResults) should be 4 but was %d\n",
			len(results.PkgResults))
	}

	// First package findings
	packageName := results.PkgResults[0].Package.Name
	if results.PkgResults[0].Package.Name != "Some Package" {
		t.Errorf("The first package should be named 'Some Package' but was named '%s'", packageName)
	}
	if len(results.PkgResults[0].Errors) != 2 {
		t.Error("There should be two SBOM issues")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorMsg != "Has no PackageSupplier field" {
		t.Errorf("Should be 'Has no PackageSupplier field' ErrorMsg")
	}
	if results.PkgResults[0].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[1].Error.ErrorMsg != "has neither Concluded License nor License From Files. Both of these cannot be absent from a package." {
		t.Errorf(
			"Should be 'has neither Concluded License nor License From Files. Both of these cannot be absent from a package.' ErrorMsg",
		)
	}
	if !slices.Equal(results.PkgResults[0].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}
	if !slices.Equal(results.PkgResults[0].Errors[1].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Second package findings
	packageName = results.PkgResults[1].Package.Name
	if results.PkgResults[1].Package.Name != "" {
		t.Errorf("The first package should be named '' but was named '%s'", packageName)
	}
	if len(results.PkgResults[1].Errors) != 2 {
		t.Error("There should only be two SBOM issues")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorMsg != "Has no PackageName field" {
		t.Errorf("Should be 'Has no PackageName field' ErrorMsg")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorMsg != "Has no PackageSupplier field" {
		t.Errorf("Should be 'Has no PackageSupplier field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}
	if !slices.Equal(results.PkgResults[1].Errors[1].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Third package findings
	packageName = results.PkgResults[2].Package.Name
	if results.PkgResults[2].Package.Name != "another package" {
		t.Errorf(
			"The second package should be named 'another package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 1 {
		t.Error("There should only be one error")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "Has no PackageSupplier field" {
		t.Errorf("Should be 'Has no PackageSupplier field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Fourth package findings
	packageName = results.PkgResults[3].Package.Name
	if results.PkgResults[3].Package.Name != "last package" {
		t.Errorf(
			"The fourth package should be named 'last package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[3].Errors) != 0 {
		t.Error("There should only be one error")
	}

	// Check results.Errs.AndPacks
	if len(results.ErrsAndPacks) != 3 {
		t.Errorf(
			"The length of results.ErrsAndPacks should be 3 but is %d",
			len(results.ErrsAndPacks),
		)
	}
	expect := []string{
		"Some Package",
		"Package-1",
		"another package",
	}
	if !slices.Equal(results.ErrsAndPacks["Has no PackageSupplier field"], expect) {
		t.Error("Wrong")
	}
	/*expect = []string{"Package"}
	if !slices.Equal(results.ErrsAndPacks["has neither Concluded License nor License From Files. Both of these cannot be absent from a package."], expect) {
		t.Error("Wrong")
	}
	expect = []string{"Package-1"}
	if !slices.Equal(results.ErrsAndPacks["Has no PackageName field"], expect) {
		t.Error("Wrong")
	}*/
}

// e2e test for the SPDX checker.
//

func TestSPDXChecker(t *testing.T) {
	sbom := "simple.json"
	checker, err := NewChecker(WithSPDXChecker())
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sboms", sbom))
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()
	results := checker.Results()

	if results.Summary.TotalSBOMPackages != 4 {
		t.Errorf("There should be 4 TotalSBOMPackages but the results only had %d\n",
			results.Summary.TotalSBOMPackages)
	}
	if results.Summary.FailedSBOMPackages != 3 {
		t.Errorf("There should be 3 FailedSBOMPackages but the results only had %d\n",
			results.Summary.FailedSBOMPackages)
	}
	if len(results.Summary.SpecSummaries) != 1 {
		t.Errorf("There should be a single specsummary for 'SPDX' but there were %d\n",
			len(results.Summary.SpecSummaries))
	}
	if results.Summary.SpecSummaries["SPDX"].Conformant != false {
		t.Errorf("The 'SPDX' spec summary should be Conformant=true but was Conformant=%t\n",
			results.Summary.SpecSummaries["SPDX"].Conformant)
	}
	if results.Summary.SpecSummaries["SPDX"].PassedChecks != 8 {
		t.Errorf("The 'SPDX' spec summary should be PassedChecks=8 but was PassedChecks=%d\n",
			results.Summary.SpecSummaries["SPDX"].PassedChecks)
	}
	if len(results.PkgResults) != 4 {
		t.Errorf("len(results.PkgResults) should be 4 but was %d\n",
			len(results.PkgResults))
	}

	// First package findings
	packageName := results.PkgResults[0].Package.Name
	if results.PkgResults[0].Package.Name != "Some Package" {
		t.Errorf("The first package should be named 'Some Package' but was named '%s'", packageName)
	}
	if len(results.PkgResults[0].Errors) != 0 {
		t.Errorf(
			"There should be no SBOM issues but there are %d\n",
			len(results.PkgResults[0].Errors),
		)
	}

	// Second package findings
	packageName = results.PkgResults[1].Package.Name
	if results.PkgResults[1].Package.Name != "" {
		t.Errorf("The first package should be named '' but was named '%s'", packageName)
	}
	if len(results.PkgResults[1].Errors) != 2 {
		t.Errorf(
			"There should be two SBOM issues but there are %d\n",
			len(results.PkgResults[1].Errors),
		)
	}
	if results.PkgResults[1].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorMsg != "Has no PackageName field" {
		t.Errorf(
			"Should be 'Has no PackageName field' ErrorMsg but was %s\n",
			results.PkgResults[1].Errors[0].Error.ErrorMsg,
		)
	}
	if results.PkgResults[1].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorMsg != "Has no PackageDownloadLocation field" {
		t.Errorf(
			"Should be 'Has no PackageDownloadLocation field' ErrorMsg but was %s\n",
			results.PkgResults[1].Errors[1].Error.ErrorMsg,
		)
	}
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}
	if !slices.Equal(results.PkgResults[1].Errors[1].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}

	// Third package findings
	packageName = results.PkgResults[2].Package.Name
	if results.PkgResults[2].Package.Name != "another package" {
		t.Errorf(
			"The second package should be named 'another package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 1 {
		t.Errorf(
			"There should be one SBOM issues but there are %d\n",
			len(results.PkgResults[2].Errors),
		)
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "Has no PackageDownloadLocation field" {
		t.Errorf(
			"Should be 'Has no PackageDownloadLocation field' ErrorMsg but was %s\n",
			results.PkgResults[2].Errors[0].Error.ErrorMsg,
		)
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}

	// Fourth package findings
	packageName = results.PkgResults[3].Package.Name
	if results.PkgResults[3].Package.Name != "last package" {
		t.Errorf(
			"The fourth package should be named 'last package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[3].Errors) != 1 {
		t.Errorf(
			"There should be one SBOM issues but there are %d\n",
			len(results.PkgResults[3].Errors),
		)
	}
	if results.PkgResults[3].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[3].Errors[0].Error.ErrorMsg != "Has no PackageDownloadLocation field" {
		t.Errorf(
			"Should be 'Has no PackageDownloadLocation field' ErrorMsg but was %s\n",
			results.PkgResults[3].Errors[0].Error.ErrorMsg,
		)
	}
	if !slices.Equal(results.PkgResults[3].Errors[0].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}
}

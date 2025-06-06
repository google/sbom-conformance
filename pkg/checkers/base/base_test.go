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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/sbom-conformance/pkg/checkers/spdx"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/testutil"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// This tests a regression of https://github.com/google/sbom-conformance/pull/31/
func TestTextSummaryDoesNotCrashWithPercentSignInPackageLevelCheckName(t *testing.T) {
	alwaysFailCheck := func(pkg *v23.Package, spec string, checkName string) []*types.NonConformantField {
		return []*types.NonConformantField{{
			Error: &types.FieldError{
				ErrorType: "some type",
				ErrorMsg:  "--%v--",
			},
			CheckName:      "some name",
			ReportedBySpec: []string{types.SPDX},
		}}
	}
	// reuse the spdxChecker to avoid redefining all of the methods
	spdxChecker := spdx.SPDXChecker{}
	spdxChecker.PkgLevelChecks = append(spdxChecker.PkgLevelChecks, &types.PackageLevelCheck{
		Name: "always fail",
		Impl: alwaysFailCheck,
	})
	baseChecker := &BaseChecker{}
	baseChecker.AddSpec(&spdxChecker)
	sbom := `{
		  "spdxVersion": "SPDX-2.3",
		  "name": "SimpleSBOM",
		  "packages": [{"name": "foo", "SPDXID": "SPDXRef-Bar"}]
		  }
		`
	err := baseChecker.SetSBOM(bytes.NewReader([]byte(sbom)))
	if err != nil {
		t.Fatalf("SetSBOM returned err: %v", err)
	}

	baseChecker.RunChecks()
	unwanted := "%!v(MISSING)"
	if summary := baseChecker.TextSummary(); strings.Contains(summary, unwanted) {
		t.Errorf("%q was detected in the string summary: %s", unwanted, summary)
	}
}

// This tests a regression of https://github.com/google/sbom-conformance/pull/31/
func TestTextSummaryDoesNotCrashWithPercentSignInTopLevelCheckName(t *testing.T) {
	alwaysFailCheck := func(doc *v23.Document, spec string) []*types.NonConformantField {
		return []*types.NonConformantField{{
			Error: &types.FieldError{
				ErrorType: "some type",
				ErrorMsg:  "--%v--",
			},
			CheckName:      "some name",
			ReportedBySpec: []string{spec},
		}}
	}
	// reuse the spdxChecker to avoid redefining all of the methods
	spdxChecker := spdx.SPDXChecker{}
	spdxChecker.TopLevelChecks = append(spdxChecker.TopLevelChecks, &types.TopLevelCheck{
		Name: "always fail",
		Impl: alwaysFailCheck,
	})
	baseChecker := &BaseChecker{}
	baseChecker.AddSpec(&spdxChecker)
	sbom := `{
		  "spdxVersion": "SPDX-2.3",
		  "name": "SimpleSBOM"
		  }
		`
	err := baseChecker.SetSBOM(bytes.NewReader([]byte(sbom)))
	if err != nil {
		t.Fatalf("SetSBOM returned err: %v", err)
	}

	baseChecker.RunChecks()
	unwanted := "%!v(MISSING)"
	if summary := baseChecker.TextSummary(); strings.Contains(summary, unwanted) {
		t.Errorf("%q was detected in the string summary: %s", unwanted, summary)
	}
}

func TestSummary(t *testing.T) {
	baseChecker, err := NewChecker(WithEOChecker(), WithGoogleChecker())
	if err != nil {
		t.Fatalf(
			"NewChecker(WithEOChecker(), WithSPDXChecker()) returned unexpected error: %v",
			err,
		)
	}
	sbom := v23.Document{
		SPDXVersion:  "SPDX-2.3",
		DocumentName: "foo",
		Packages: []*v23.Package{
			{PackageSPDXIdentifier: "foo"},
			{PackageSPDXIdentifier: "bar"},
		},
	}
	baseChecker.SetSPDXDocument(&sbom)
	baseChecker.RunChecks()

	expected := &types.Summary{
		TotalSBOMPackages:  2,
		FailedSBOMPackages: 2,
		SpecSummaries: map[string]*types.SpecSummary{
			"EO": {
				Conformant:   false,
				PassedChecks: 0,
				TotalChecks:  7,
			},
			"Google": {
				Conformant:   false,
				PassedChecks: 3,
				TotalChecks:  11,
			},
		},
	}
	if diff := cmp.Diff(expected, baseChecker.Results().Summary); diff != "" {
		t.Errorf("Encountered checker.Results().Summary diff (-want +got):\n%s", diff)
	}
}

func TestPackageLevelChecksWithSameErrorMessageButDifferentNamesNotDeduped(t *testing.T) {
	// all SPDX checks should pass here
	sbom := `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo",
						"downloadLocation": "foo.com"
					}]
				}`
	baseChecker := &BaseChecker{}
	err := baseChecker.SetSBOM(bytes.NewReader([]byte(sbom)))
	if err != nil {
		t.Fatalf("SetSBOM returned err: %v", err)
	}
	spdxChecker := spdx.SPDXChecker{Name: types.SPDX}
	spdxChecker.PkgLevelChecks = []*types.PackageLevelCheck{
		{
			Name: "a_name",
			Impl: func(sbomPackage *v23.Package, spec, checkName string) []*types.NonConformantField {
				return []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "does_not_matter",
						ErrorMsg:  "duplicate_message",
					},
					CheckName:      checkName,
					ReportedBySpec: []string{spec},
				}}
			},
		},
		{
			Name: "some_other_name",
			Impl: func(sbomPackage *v23.Package, spec, checkName string) []*types.NonConformantField {
				return []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "does_not_matter",
						ErrorMsg:  "duplicate_message",
					},
					CheckName:      checkName,
					ReportedBySpec: []string{spec},
				}}
			},
		},
	}

	baseChecker.AddSpec(&spdxChecker)
	baseChecker.RunChecks()
	results := baseChecker.Results()

	want := []*types.PkgResult{{
		Package: &types.Package{Name: "foo", SpdxID: "foo"},
		Errors: []*types.NonConformantField{
			{
				Error: &types.FieldError{
					ErrorType: "does_not_matter",
					ErrorMsg:  "duplicate_message",
				},
				CheckName:      "a_name",
				ReportedBySpec: []string{"SPDX"},
			},
			{
				Error: &types.FieldError{
					ErrorType: "does_not_matter",
					ErrorMsg:  "duplicate_message",
				},
				CheckName:      "some_other_name",
				ReportedBySpec: []string{"SPDX"},
			},
		},
	}}
	if diff := cmp.Diff(want, results.PkgResults); diff != "" {
		t.Errorf("Encountered results.TopLevelChecks diff (-want +got):\n%s", diff)
	}
}

func TestTopLevelChecksWithSameErrorMessageButDifferentNamesNotDeduped(t *testing.T) {
	// all SPDX checks should pass here
	sbom := `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC (foo@bar.com)", "Tool: tool-v5"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`
	baseChecker := &BaseChecker{}
	err := baseChecker.SetSBOM(bytes.NewReader([]byte(sbom)))
	if err != nil {
		t.Fatalf("SetSBOM returned err: %v", err)
	}
	spdxChecker := spdx.SPDXChecker{Name: types.SPDX}
	spdxChecker.TopLevelChecks = []*types.TopLevelCheck{
		{
			Name: "a_name",
			Impl: func(doc *v23.Document, spec string) []*types.NonConformantField {
				return []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "does_not_matter",
						ErrorMsg:  "duplicate_message",
					},
					ReportedBySpec: []string{spec},
				}}
			},
		},
		{
			Name: "a_different_name",
			Impl: func(doc *v23.Document, spec string) []*types.NonConformantField {
				return []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "does_not_matter",
						ErrorMsg:  "duplicate_message",
					},
					ReportedBySpec: []string{spec},
				}}
			},
		},
	}

	baseChecker.AddSpec(&spdxChecker)
	baseChecker.RunChecks()
	failedTopLevelChecks := testutil.ExtractFailedTopLevelChecks(
		baseChecker.Results().TopLevelChecks,
	)

	want := []testutil.FailedTopLevelCheck{
		{
			Name:  "a_name",
			Specs: []string{types.SPDX},
		},
		{
			Name:  "a_different_name",
			Specs: []string{types.SPDX},
		},
	}
	if diff := cmp.Diff(want, failedTopLevelChecks, testutil.FailedTopLevelCheckOpts...); diff != "" {
		t.Errorf("Encountered results.TopLevelChecks diff (-want +got):\n%s", diff)
	}
}

// Most tests in this file use basechecker.SetSBOM. This test exercises
// the basechecker.SetSPDXDocument(v23.Document) initialization.
func TestSetSpdxDocument(t *testing.T) {
	baseChecker, err := NewChecker(WithEOChecker())
	if err != nil {
		t.Fatalf("NewChecker(WithEOChecker()) returned unexpected error: %v", err)
	}
	sbom := v23.Document{
		SPDXVersion:  "SPDX-2.3",
		DocumentName: "foo",
		Packages:     []*v23.Package{{PackageSPDXIdentifier: "foo"}},
	}
	baseChecker.SetSPDXDocument(&sbom)
	baseChecker.RunChecks()
	// sanity check for success
	if results := baseChecker.Results(); len(results.ErrsAndPacks) == 0 {
		t.Errorf(
			"len(baseChecker.Results().ErrsAndPacks) == 0, which indicates that no checks were run. The text summary is:\n%s",
			results.TextSummary,
		)
	}
}

func TestSetSBOMIOFailure(t *testing.T) {
	baseChecker, err := NewChecker(WithEOChecker())
	if err != nil {
		t.Fatalf("NewChecker(WithEOChecker()) returned unexpected error: %v", err)
	}
	err = baseChecker.SetSBOM(testutil.BadReader{})
	if err == nil {
		t.Errorf("Expected error from SetSBOM, but none was returned")
	}
}

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(tt.specs...)
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(tt.expected, checker.Results().PkgResults, testutil.PkgResultsOpts...); diff != "" {
				t.Errorf("Encountered checker.Results() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// Note: these parse failures should either be folded into the quality evaluation,
// or they should return more specific errors.
func TestParseFailure(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected error
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
			expected: ErrParseFailure,
		},
		{
			name: "Missing spdxVersion causes parse failure",
			sbom: `{
				"name": "SimpleSBOM"
			}`,
			expected: ErrSPDXVersion,
		},
		{
			name: "Empty spdxVersion causes parse failure",
			sbom: `{
				"name": "SimpleSBOM",
				"spdxVersion": ""
			}`,
			expected: ErrSPDXVersion,
		},
		{
			name: "Invalid spdxVersion causes parse failure",
			sbom: `{
				"name": "SimpleSBOM",
				"spdxVersion": "SPDX-2.3.1"
			}`,
			expected: ErrSPDXVersion,
		},
		{
			name: "Empty package in relationship causes parse failure",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": [],
					"created": ""
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						}
				],
				"relationships": [{
					"spdxElementId": "",
					"relationshipType": "DESCRIBES",
					"relatedSpdxElement": "SPDXRef-foo"
				}]
			}`,
			expected: ErrParseFailure,
		},
		{
			name: "SPDXID without SPDXRef prefix fails to parse",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": [],
					"created": ""
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "foo"
						}
				]
			}`,
			expected: ErrParseFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithEOChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if !errors.Is(err, tt.expected) {
				t.Fatalf("SetSBOM did not return expected error. Got %v, want %v", err, tt.expected)
			}
		})
	}
}

func TestGoogleTopLevelChecks(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []testutil.FailedTopLevelCheck
	}{
		{
			name: "Google data license, SPDXID, document name, document namespace, creator, and created checks pass",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
		},
		{
			name: "Google data license, SPDXID, and document name, document namespace, creator, and created checks fail because they are missing",
			sbom: `{
				"spdxVersion": "SPDX-2.3"
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the data license is correct",
					Specs: []string{"Google"},
				},
				{
					Name:  "Check that the SBOM has the correct SPDX Identifier",
					Specs: []string{"Google"},
				},
				{
					Name:  "Check that the SBOM has a Document Name",
					Specs: []string{"Google"},
				},
				{
					Name:  "Check that the SBOM has a Google Document Namespace",
					Specs: []string{"Google"},
				},
				{
					Name:  "Check that the SBOM has a Google Creator, a Tool creator, and no Person creator",
					Specs: []string{"Google"},
				},
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google data license check fails because it has the wrong value",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.1",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the data license is correct",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google SPDXID check fails because it has the wrong value",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-foo",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has the correct SPDX Identifier",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google Document Namespace check fails because it has the wrong value",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Document Namespace",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google Document Namespace check fails because it has no uuid",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Document Namespace",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google Document Namespace check fails because the uuid is not valid",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Document Namespace",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google creator check fails because the organization is missing",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Creator, a Tool creator, and no Person creator",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google creator check fails because the tool is missing",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Creator, a Tool creator, and no Person creator",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google creator check fails because a person creator is provided",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool", "Person: some-person"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Creator, a Tool creator, and no Person creator",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google creator check fails because the organization is wrong",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Google Creator, a Tool creator, and no Person creator",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google creator check passes with two organizations",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool", "Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
		},
		{
			name: "Google timestamp check fails because it is not UTC",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "1994-11-05T08:15:30-05:00"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Google timestamp check fails because UTC is not explicit",
			// timestamp is missing 'Z' suffix
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Other Licensing Info section is conformant",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-foo.abc123-.XYZ",
						"extractedText": "foo license"
					},
					{
						"licenseId": "LicenseRef-bar",
						"extractedText": "bar license"
					}
				]
			}`,
		},
		{
			name: "Licensing Info section is not conformant because of a missing licenseId",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"extractedText": "foo license"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because of a missing license text",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-foo"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because of an empty license text",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-foo",
						"extractedText": ""
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because licenseId is missing the idstring",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-",
						"extractedText": "xyz"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because licenseId has invalid chars",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-a_a",
						"extractedText": "foo"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"Google"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant licenseId is not unique",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://spdx.google/cf736fd8-ceec-4cb5-b1aa-cb40ef942f18",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Google LLC", "Tool: some-tool"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-a",
						"extractedText": "foo"
					},
					{
						"licenseId": "LicenseRef-a",
						"extractedText": "foo"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"Google"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithGoogleChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(
				tt.expected,
				testutil.ExtractFailedTopLevelChecks(checker.Results().TopLevelChecks),
				testutil.FailedTopLevelCheckOpts...,
			); diff != "" {
				t.Errorf(
					"Encountered checker.TopLevelResults() diff (-want +got):\n%s",
					diff,
				)
			}
		})
	}
}

func TestSPDXTopLevelChecks(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []testutil.FailedTopLevelCheck
	}{
		{
			name: "SPDX name, namespace, SPDXID, creator, and timestamp checks pass",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC (foo@bar.com)", "Tool: tool-v5"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
		},
		{
			name: "SPDX name, namespace, SPDXID, creator, and timestamp checks fail because they are missing",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"creationInfo": {}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Document Name",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM has a valid Document Namespace",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM has the correct SPDXIdentifier",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX name, namespace, SPDXID, creator, and timestamp checks fail because they are empty",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "",
				"SPDXID": "SPDXRef-",
				"documentNamespace": "",
				"creationInfo": {
					"creators": [],
					"created": ""
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a Document Name",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM has a valid Document Namespace",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM has the correct SPDXIdentifier",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX namespace check fails because it does not have a scheme",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "name",
				"documentNamespace": "google.com",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a valid Document Namespace",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX namespace check fails because it has a '#'",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "name",
      "documentNamespace": "https://google.com#subpath",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a valid Document Namespace",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX namespace check fails because it is not an RFC 3986 url",
			// invalid character in DocumentNamespace scheme
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "name",
				"documentNamespace": " https://google.com",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has a valid Document Namespace",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX SPDXID check fails because it is not SPDXRef-DOCUMENT",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "foo",
				"SPDXID": "SPDXRef-foo",
				"documentNamespace": "https://foo.com",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has the correct SPDXIdentifier",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because there is no creator component",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: "],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because the type is unrecognized",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Foo: Bar"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because the Tool does not contain a version",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Tool: Bar"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because the Tool contains an empty version",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Tool: Bar-"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Empty email is allowed by Creator check",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar ()", "Organization: Bar"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
		},
		{
			name: "Email group must be last parenthesis group in string -- allowed",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar (inc) (sbom@google.com)"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
		},
		{
			name: "Email group must be last parenthesis group in string -- failed",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar (inc) (inc)"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Email group must be last parenthesis group in string -- passed with empty email",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar (inc) ()"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
		},
		{
			name: "Creator check fails because of an invalid email -- missing domain",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar (foo@)"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because of an invalid email -- missing local part",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar (@foo)"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because of an invalid email -- missing @ separator",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Bar (foo)"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Creator check fails because tool has email",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Tool: Bar (foo@bar.com)"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator and that they are formatted correctly",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Other Licensing Info section is conformant",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-foo.abc123-.XYZ",
						"extractedText": "foo license"
					},
					{
						"licenseId": "LicenseRef-bar",
						"extractedText": "bar license"
					}
				]
			}`,
		},
		{
			name: "Licensing Info section is not conformant because of a missing licenseId",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"extractedText": "foo license"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because of a missing license text",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-foo"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because of an empty license text",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-foo",
						"extractedText": ""
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because licenseId is missing the idstring",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-",
						"extractedText": "xyz"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant because licenseId has invalid chars",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-a_a",
						"extractedText": "foo"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "Licensing Info section is not conformant licenseId is not unique",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				},
				"hasExtractedLicensingInfos": [
					{
						"licenseId": "LicenseRef-a",
						"extractedText": "foo"
					},
					{
						"licenseId": "LicenseRef-a",
						"extractedText": "foo"
					}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that Other Licensing Information section is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "DataLicense is missing",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the data license is correct",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "DataLicense has wrong value",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "foo",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25Z"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the data license is correct",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX timestamp check fails because it is not UTC",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "1994-11-05T08:15:30-05:00"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX timestamp check fails because UTC is not explicit",
			// timestamp is missing 'Z' suffix
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo LLC"],
					"created": "2025-04-08T01:25:25"
				}
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM's timestamp is conformant",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX Package SPDXID is not unique",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "2025-04-08T01:25:25Z"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						},
 						{
								"name": "Bar",
								"SPDXID": "SPDXRef-bar"
						},
 						{
								"name": "Baz",
								"SPDXID": "SPDXRef-foo"
						}
				]
			}`,
			expected: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the package SPDX identifiers are unique",
					Specs: []string{"SPDX"},
				},
			},
		},
		{
			name: "SPDX Package SPDXID is unique",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"documentNamespace": "https://foo.com",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "2025-04-08T01:25:25Z"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						},
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-bar"
						}
				]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithSPDXChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(
				tt.expected,
				testutil.ExtractFailedTopLevelChecks(checker.Results().TopLevelChecks),
				testutil.FailedTopLevelCheckOpts...,
			); diff != "" {
				t.Errorf(
					"Encountered checker.TopLevelResults() diff (-want +got):\n%s",
					diff,
				)
			}
		})
	}
}

func TestEOTopLevelChecks(t *testing.T) {
	tests := []struct {
		name       string
		sbom       string
		wantFailed []testutil.FailedTopLevelCheck
	}{
		{
			name: "Missing fields cause author and timestamp checks to fail",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM"
			}`,
			wantFailed: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator",
					Specs: []string{"EO"},
				},
				{
					Name:  "Check that the SBOM has a timestamp",
					Specs: []string{"EO"},
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
				}
			}`,
			wantFailed: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that the SBOM has at least one creator",
					Specs: []string{"EO"},
				},
				{
					Name:  "Check that the SBOM has a timestamp",
					Specs: []string{"EO"},
				},
			},
		},
		{
			name: "Not all packages have a relationship",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						},
 						{
								"name": "Bar",
								"SPDXID": "SPDXRef-bar"
						}
				],
				"relationships": [{
					"spdxElementId": "SPDXRef-Document",
					"relationshipType": "DESCRIBES",
					"relatedSpdxElement": "SPDXRef-foo"
				}]
			}`,
			wantFailed: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that each SBOM package has a relationship",
					Specs: []string{"EO"},
				},
			},
		},
		{
			name: "Author, timestamp, and relationship checks pass",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						},
 						{
								"name": "Bar",
								"SPDXID": "SPDXRef-bar"
						}
				],
				"relationships": [
 						{
								"spdxElementId": "SPDXRef-Document",
								"relationshipType": "DESCRIBES",
								"relatedSpdxElement": "SPDXRef-foo"
						},
 						{
								"spdxElementId": "SPDXRef-bar",
								"relationshipType": "DEPENDS_ON",
								"relatedSpdxElement": "SPDXRef-foo"
						}
				]
			}`,
		},
		{
			name: "Relationship check allows any relationship type and NONE components",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						},
 						{
								"name": "Bar",
								"SPDXID": "SPDXRef-bar"
						}
				],
				"relationships": [
 						{
								"spdxElementId": "SPDXRef-Document",
								"relationshipType": "OPTIONAL_COMPONENT_OF",
								"relatedSpdxElement": "SPDXRef-foo"
						},
 						{
								"spdxElementId": "SPDXRef-bar",
								"relationshipType": "DEPENDS_ON",
								"relatedSpdxElement": "NONE"
						}
				]
			}`,
		},
		{
			name: "Self relationships not allowed",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						}
				],
				"relationships": [
 						{
								"spdxElementId": "SPDXRef-foo",
								"relationshipType": "DEPENDS_ON",
								"relatedSpdxElement": "SPDXRef-foo"
						}
				]
			}`,
			wantFailed: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that each SBOM package has a relationship",
					Specs: []string{"EO"},
				},
			},
		},
		{
			name: "Self NONE relationship not allowed",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						}
				],
				"relationships": [
 						{
								"spdxElementId": "NONE",
								"relationshipType": "DEPENDS_ON",
								"relatedSpdxElement": "NONE"
						}
				]
			}`,
			wantFailed: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that each SBOM package has a relationship",
					Specs: []string{"EO"},
				},
			},
		},
		{
			name: "NOASSERTION is not allowed for relationship check",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"creationInfo": {
					"creators": ["Organization: Foo"],
					"created": "some timestamp"
				},
				"packages": [
 						{
								"name": "Foo",
								"SPDXID": "SPDXRef-foo"
						}
				],
				"relationships": [
 						{
								"spdxElementId": "SPDXRef-foo",
								"relationshipType": "DEPENDS_ON",
								"relatedSpdxElement": "NOASSERTION"
						}
				]
			}`,
			wantFailed: []testutil.FailedTopLevelCheck{
				{
					Name:  "Check that each SBOM package has a relationship",
					Specs: []string{"EO"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithEOChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
			if err != nil {
				t.Fatalf("SetSBOM returned err: %v", err)
			}

			checker.RunChecks()
			if diff := cmp.Diff(
				tt.wantFailed,
				testutil.ExtractFailedTopLevelChecks(checker.Results().TopLevelChecks),
				testutil.FailedTopLevelCheckOpts...,
			); diff != "" {
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
					Name:           "Check that SBOM packages have a valid version",
					FailedPackages: 1,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have a name",
					FailedPackages: 1,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have external references",
					FailedPackages: 1,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that the package has a supplier",
					FailedPackages: 1,
					Specs:          []string{"EO"},
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
					Name:           "Check that SBOM packages have a valid version",
					FailedPackages: 2,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have a name",
					FailedPackages: 2,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have external references",
					FailedPackages: 2,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that the package has a supplier",
					FailedPackages: 2,
					Specs:          []string{"EO"},
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
					Name:           "Check that SBOM packages have a valid version",
					FailedPackages: 0,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have a name",
					FailedPackages: 0,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have external references",
					FailedPackages: 0,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that the package has a supplier",
					FailedPackages: 0,
					Specs:          []string{"EO"},
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
					Name:           "Check that SBOM packages have a valid version",
					FailedPackages: 0,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages have a name",
					FailedPackages: 0,
					Specs:          []string{"EO", "SPDX"},
				},
				{
					Name:           "Check that SBOM packages have external references",
					FailedPackages: 0,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that the package has a supplier",
					FailedPackages: 0,
					Specs:          []string{"EO"},
				},
				{
					Name:           "Check that SBOM packages' ID is present and conformant",
					FailedPackages: 0,
					Specs:          []string{"SPDX"},
				},
				{
					Name:           "Check that SBOM packages' filesAnalyzed is true if packageVerificationCode is present",
					FailedPackages: 0,
					Specs:          []string{"SPDX"},
				},
				{
					Name:           "Check that SBOM packages have a download location",
					FailedPackages: 0,
					Specs:          []string{"SPDX"},
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
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
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
			name: "Supplier is NOASSERTION fails check",
			sbom: `{
				"spdxVersion": "SPDX-2.3",
				"name": "SimpleSBOM",
				"packages": [{
					"name": "Foo",
					"SPDXID": "SPDXRef-foo",
					"versionInfo": "v1",
					"supplier": "NOASSERTION",
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
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
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

func TestGooglePkgResults(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []*types.PkgResult
	}{
		{
			name: "Google package name, SPDXID, supplier, and license checks pass",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-abcXYZ123.-",
							"supplier": "Organization: Foo",
							"licenseConcluded": "LicenseRef-foo"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"supplier": "Organization: bar",
							"licenseInfoFromFiles": ["LicenseRef-foo", "LicenseRef-bar"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
					Errors:  []*types.NonConformantField{},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors:  []*types.NonConformantField{},
				},
			},
		},
		{
			name: "Google package name, SPDXID, supplier, and license checks fail because they are empty",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"SPDXID": "SPDXRef-",
						"licenseConcluded": "",
						"licenseInfoFromFiles": []
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "", SpdxID: ""},
				Errors: []*types.NonConformantField{
					{
						Error: &types.FieldError{
							ErrorType: "missingField",
							ErrorMsg:  "Has no PackageName field",
						},
						CheckName:      "Check that SBOM packages have a name",
						ReportedBySpec: []string{"Google"},
					},
					{
						Error: &types.FieldError{
							ErrorType: "missingField",
							ErrorMsg:  "Has no PackageSPDXIdentifier field",
						},
						CheckName:      "Check that SBOM packages' ID is present and conformant",
						ReportedBySpec: []string{"Google"},
					},
					{
						Error: &types.FieldError{
							ErrorType: "missingField",
							ErrorMsg:  "Has no PackageSupplier field",
						},
						CheckName:      "Check that SBOM packages have a valid supplier",
						ReportedBySpec: []string{"Google"},
					},
					{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					},
				},
			}},
		},
		{
			name: "Google package SPDXID check fails because it contains invalid chars",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-foo_bar",
							"supplier": "Organization: Foo",
							"licenseConcluded": "LicenseRef-foo"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-foo$bar",
							"supplier": "Organization: Foo",
							"licenseConcluded": "LicenseRef-foo"
						},
						{
							"name": "baz",
							"SPDXID": "SPDXRef-foo,bar",
							"supplier": "Organization: Foo",
							"licenseConcluded": "LicenseRef-foo"
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "foo_bar"},
					Errors: []*types.NonConformantField{
						{
							Error: &types.FieldError{
								ErrorType: "formatError",
								ErrorMsg: "SPDX Identifier is non-conformant. " +
									"It should have letters, numbers, \".\" and/or \"-\"",
							},
							CheckName:      "Check that SBOM packages' ID is present and conformant",
							ReportedBySpec: []string{"Google"},
						},
					},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "foo$bar"},
					Errors: []*types.NonConformantField{
						{
							Error: &types.FieldError{
								ErrorType: "formatError",
								ErrorMsg: "SPDX Identifier is non-conformant. " +
									"It should have letters, numbers, \".\" and/or \"-\"",
							},
							CheckName:      "Check that SBOM packages' ID is present and conformant",
							ReportedBySpec: []string{"Google"},
						},
					},
				},
				{
					Package: &types.Package{Name: "baz", SpdxID: "foo,bar"},
					Errors: []*types.NonConformantField{
						{
							Error: &types.FieldError{
								ErrorType: "formatError",
								ErrorMsg: "SPDX Identifier is non-conformant. " +
									"It should have letters, numbers, \".\" and/or \"-\"",
							},
							CheckName:      "Check that SBOM packages' ID is present and conformant",
							ReportedBySpec: []string{"Google"},
						},
					},
				},
			},
		},
		{
			name: "Google supplier check fails because the supplier value is empty",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "Organization: ",
						"licenseConcluded": "LicenseRef-foo"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageSupplier field",
					},
					CheckName:      "Check that SBOM packages have a valid supplier",
					ReportedBySpec: []string{"Google"},
				}},
			}},
		},
		{
			name: "Google supplier check fails because the type is not valid",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "Foo: bar",
						"licenseConcluded": "LicenseRef-foo"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageSupplier field",
					},
					CheckName:      "Check that SBOM packages have a valid supplier",
					ReportedBySpec: []string{"Google"},
				}},
			}},
		},
		{
			name: "Google Supplier check passes for NOASSERTION",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo",
						"supplier": "NOASSERTION",
						"licenseConcluded": "LicenseRef-foo"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo"},
				Errors:  []*types.NonConformantField{},
			}},
		},
		{
			name: "Google license checks pass for NONE",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-abcXYZ123.-",
							"supplier": "Organization: Foo",
							"licenseConcluded": "NONE"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"supplier": "Organization: bar",
							"licenseInfoFromFiles": ["NONE"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
					Errors:  []*types.NonConformantField{},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors:  []*types.NonConformantField{},
				},
			},
		},
		{
			name: "Google license checks fail for NOASSERTION",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-abcXYZ123.-",
							"supplier": "Organization: Foo",
							"licenseConcluded": "NOASSERTION"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"supplier": "Organization: bar",
							"licenseInfoFromFiles": ["NOASSERTION"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
			},
		},
		{
			name: "Google license checks fail for SPDX License List references",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-abcXYZ123.-",
							"supplier": "Organization: Foo",
							"licenseConcluded": "CDDL-1.0"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"supplier": "Organization: bar",
							"licenseInfoFromFiles": ["CDDL-1.0"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
			},
		},
		{
			name: "Google license checks must pass for all licenseInfoFromFiles",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"supplier": "Organization: bar",
							"licenseInfoFromFiles": ["NONE", "NOASSERTION"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
			},
		},
		{
			name: "Google license check fails for license references from other documents",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-abcXYZ123.-",
							"supplier": "Organization: Foo",
							"licenseConcluded": "DocumentRef-foo:LicenseRef"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"supplier": "Organization: bar",
							"licenseInfoFromFiles": ["DocumentRef-foo:LicenseRef"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors: []*types.NonConformantField{{
						Error: &types.FieldError{
							ErrorType: "licenseError",
							ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
								"contain references to custom license expressions",
						},
						CheckName:      "Check that SBOM packages' licenses are conformant",
						ReportedBySpec: []string{"Google"},
					}},
				},
			},
		},
		{
			name: "Google license check passes if one license field is conformant",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-abcXYZ123.-",
							"supplier": "Organization: Foo",
							"licenseConcluded": "LicenseRef-foo",
							"licenseInfoFromFiles": ["NOASSERTION"]
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
					Errors:  []*types.NonConformantField{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithGoogleChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
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

func TestSPDXPkgResults(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []*types.PkgResult
	}{
		{
			name: "All SPDX package level checks pass",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-abcXYZ123.-",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
				Errors:  []*types.NonConformantField{},
			}},
		},
		{
			name: "Package name check fails because it is missing",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"SPDXID": "SPDXRef-foo",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageName field",
					},
					CheckName:      "Check that SBOM packages have a name",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package name check fails because it is empty",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "",
						"SPDXID": "SPDXRef-foo",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageName field",
					},
					CheckName:      "Check that SBOM packages have a name",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package SPDXID check fails because it is missing",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageSPDXIdentifier field",
					},
					CheckName:      "Check that SBOM packages' ID is present and conformant",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package SPDXID check fails because the idstring is empty",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: ""},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageSPDXIdentifier field",
					},
					CheckName:      "Check that SBOM packages' ID is present and conformant",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		// The following three tests check common invalid characters for the SPDXID
		// field.
		{
			name: "Package SPDXID check fails because it contains an underscore",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo_bar",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo_bar"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "formatError",
						ErrorMsg: "SPDX Identifier is non-conformant. " +
							"It should have letters, numbers, \".\" and/or \"-\"",
					},
					CheckName:      "Check that SBOM packages' ID is present and conformant",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package SPDXID check fails because it contains a dollar sign",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo$bar",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo$bar"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "formatError",
						ErrorMsg: "SPDX Identifier is non-conformant. " +
							"It should have letters, numbers, \".\" and/or \"-\"",
					},
					CheckName:      "Check that SBOM packages' ID is present and conformant",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package SPDXID check fails because it contains a comma",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo,bar",
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo,bar"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "formatError",
						ErrorMsg: "SPDX Identifier is non-conformant. " +
							"It should have letters, numbers, \".\" and/or \"-\"",
					},
					CheckName:      "Check that SBOM packages' ID is present and conformant",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package download location check fails because it is missing",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageDownloadLocation field",
					},
					CheckName:      "Check that SBOM packages have a download location",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package download location check fails because it is empty",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-foo",
						"downloadLocation": ""
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "foo"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "missingField",
						ErrorMsg:  "Has no PackageDownloadLocation field",
					},
					CheckName:      "Check that SBOM packages have a download location",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			// These are allowed by
			// https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field
			name: "Package download location passes for NOASSERTION and NONE",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [
						{
							"name": "foo",
							"SPDXID": "SPDXRef-foo",
							"downloadLocation": "NONE"
						},
						{
							"name": "bar",
							"SPDXID": "SPDXRef-bar",
							"downloadLocation": "NOASSERTION"
						}
					]
				}`,
			expected: []*types.PkgResult{
				{
					Package: &types.Package{Name: "foo", SpdxID: "foo"},
					Errors:  []*types.NonConformantField{},
				},
				{
					Package: &types.Package{Name: "bar", SpdxID: "bar"},
					Errors:  []*types.NonConformantField{},
				},
			},
		},
		{
			name: "Package filesAnalyzed check fails because it is false and verificationCode is present",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-abcXYZ123.-",
						"filesAnalyzed": false,
						"packageVerificationCode": {"packageVerificationCodeValue": "xyz"},
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
				Errors: []*types.NonConformantField{{
					Error: &types.FieldError{
						ErrorType: "wrongValue",
						ErrorMsg:  "filesAnalyzed must be true",
					},
					CheckName:      "Check that SBOM packages' filesAnalyzed is true if packageVerificationCode is present",
					ReportedBySpec: []string{"SPDX"},
				}},
			}},
		},
		{
			name: "Package filesAnalyzed check passes because it is true and verificationCode is present",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-abcXYZ123.-",
						"filesAnalyzed": true,
						"packageVerificationCode": {"packageVerificationCodeValue": "xyz"},
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
				Errors:  []*types.NonConformantField{},
			}},
		},
		{
			// the default value for filesAnalyzed is true
			name: "Package filesAnalyzed check passes because it is missing and verificationCode is present",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-abcXYZ123.-",
						"packageVerificationCode": {"packageVerificationCodeValue": "xyz"},
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
				Errors:  []*types.NonConformantField{},
			}},
		},
		{
			// this tests that verificationCode is not required.
			name: "Package filesAnalyzed check passes because it is true and verificationCode is missing",
			sbom: `{
					"name": "SimpleSBOM",
					"spdxVersion": "SPDX-2.3",
					"packages": [{
						"name": "foo",
						"SPDXID": "SPDXRef-abcXYZ123.-",
						"filesAnalyzed": true,
						"downloadLocation": "foo.com"
					}]
				}`,
			expected: []*types.PkgResult{{
				Package: &types.Package{Name: "foo", SpdxID: "abcXYZ123.-"},
				Errors:  []*types.NonConformantField{},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewChecker(WithSPDXChecker())
			if err != nil {
				t.Fatalf("NewChecker failed with error: %v", err)
			}
			err = checker.SetSBOM(bytes.NewReader([]byte(tt.sbom)))
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
	err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()
	results := checker.Results()

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
	err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()
	results := checker.Results()

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
	err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()
	results := checker.Results()

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
	if len(results.PkgResults[1].Errors) != 1 {
		t.Errorf(
			"There should be one SBOM issues but there are %d\n",
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
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"SPDX"}) {
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
	if len(results.PkgResults[2].Errors) != 0 {
		t.Errorf(
			"There should be zero SBOM issues but there are %d\n",
			len(results.PkgResults[2].Errors),
		)
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
		t.Errorf(
			"There should be zero SBOM issues but there are %d\n",
			len(results.PkgResults[3].Errors),
		)
	}
}

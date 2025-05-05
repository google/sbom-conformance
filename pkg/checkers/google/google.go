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

package google

import (
	"github.com/google/sbom-conformance/pkg/checkers/common"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type GoogleChecker struct {
	Name           string                      `json:"name"`
	TopLevelChecks []*types.TopLevelCheck      `json:"topLevelChecks"`
	PkgLevelChecks []*types.PackageLevelCheck  `json:"pkgLevelChecks"`
	Issues         []*types.NonConformantField `json:"issues"`

	// Contains results of the packages in the SBOM.
	PkgResults []*types.PkgResult `json:"pkgResults"`
}

func (googleChecker *GoogleChecker) InitChecks() {
	topLevelChecks := []*types.TopLevelCheck{
		{
			Name: "Check that the data license is correct",
			Impl: common.SBOMHasCorrectDataLicense,
		},
		{
			Name: "Check that the SBOM has the correct SPDX Identifier",
			Impl: common.SBOMHasCorrectSPDXIdentifier,
		},
		{
			Name: "Check that the SBOM has a Document Name",
			Impl: common.SBOMHasDocumentName,
		},
		{
			Name: "Check that the SBOM has a Google Document Namespace",
			Impl: SBOMHasGoogleDocumentNamespace,
		},
		{
			Name: "Check that the SBOM has a Google Creator, a Tool creator, and no Person creator",
			Impl: SBOMHasGoogleCreators,
		},
		{
			Name: "Check that the SBOM's timestamp is conformant",
			Impl: common.CheckCreatedIsConformant,
		},
		{
			Name: "Check that Other Licensing Information section is conformant",
			Impl: common.CheckOtherLicensingInformationSection,
		},
	}
	googleChecker.TopLevelChecks = topLevelChecks

	packageLevelChecks := []*types.PackageLevelCheck{
		{
			// this needs to be tested
			Name: "Check that SBOM packages have a name",
			Impl: common.MustHaveName,
		},
		{
			// this needs to be tested
			Name: "Check that SBOM packages' ID is correctly formatted",
			Impl: common.CheckSPDXID,
		},
		{
			// this needs to be renamed to CheckPackageSupplier and the implementation simplified.
			Name: "Check that SBOM packages have specified the supplier as Google",
			Impl: CheckPackageOriginator,
		},
		{
			// this needs to be updated to check that a custom license text is used
			Name: "Check that SBOM packages have not left both PackageLicenseConcluded and PackageLicenseInfoFromFiles empty",
			Impl: CheckConcludedLicense,
		},
	}

	googleChecker.PkgLevelChecks = packageLevelChecks
}

func (googleChecker *GoogleChecker) RunTopLevelChecks(doc *v23.Document) {
	for _, check := range googleChecker.TopLevelChecks {
		issues := check.Impl(doc, types.Google)
		for _, issue := range issues {
			issue.CheckName = check.Name
		}
		googleChecker.Issues = append(googleChecker.Issues, issues...)
	}
}

func (googleChecker *GoogleChecker) GetIssues() []*types.NonConformantField {
	return googleChecker.Issues
}

func (googleChecker *GoogleChecker) GetPackages() []*types.PkgResult {
	return googleChecker.PkgResults
}

// Returns the spdxCheckers checks as strings.
func (googleChecker *GoogleChecker) GetChecks() []string {
	allChecks := make([]string, 0)
	for _, topLevelCheck := range googleChecker.TopLevelChecks {
		allChecks = append(allChecks, topLevelCheck.Name)
	}
	for _, pkgLevelCheck := range googleChecker.PkgLevelChecks {
		allChecks = append(allChecks, pkgLevelCheck.Name)
	}
	return allChecks
}

func (googleChecker *GoogleChecker) GetTopLevelChecks() []string {
	checks := make([]string, 0)
	for _, topLevelCheck := range googleChecker.TopLevelChecks {
		checks = append(checks, topLevelCheck.Name)
	}
	return checks
}

func (googleChecker *GoogleChecker) GetPackageLevelChecks() []string {
	checks := make([]string, 0)
	for _, topLevelCheck := range googleChecker.PkgLevelChecks {
		checks = append(checks, topLevelCheck.Name)
	}
	return checks
}

func (googleChecker *GoogleChecker) SpecName() string {
	return googleChecker.Name
}

func (googleChecker *GoogleChecker) CheckPackages(doc *v23.Document) {
	googleChecker.PkgResults = util.RunPkgLevelChecks(
		doc,
		googleChecker.PkgLevelChecks,
		googleChecker.Name,
	)
}

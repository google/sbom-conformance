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
	"fmt"
	"slices"
	"strings"

	"github.com/google/sbom-conformance/pkg/checkers/common"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	"github.com/google/uuid"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const (
	googleDocNamespacePrefix  string = "https://spdx.google/"
	googleCreatorOrganization string = "Google LLC"
)

func SBOMHasGoogleCreators(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.CreationInfo == nil {
		issues = append(issues, types.CreateFieldError(types.Creator, spec))
		return issues
	}
	var foundTool, foundGoogleCreator, foundPerson bool
	for _, creator := range doc.CreationInfo.Creators {
		foundTool = foundTool || creator.CreatorType == "Tool"
		foundPerson = foundPerson || creator.CreatorType == "Person"
		foundGoogleCreator = foundGoogleCreator ||
			(creator.CreatorType == "Organization" && creator.Creator == googleCreatorOrganization)
	}
	if !foundTool {
		issues = append(issues, types.MandatoryPackageFieldError(types.CreatorTool, spec))
	}
	if foundPerson {
		issue := types.NonConformantField{
			Error: &types.FieldError{
				ErrorType: "FieldNotAllowed",
				ErrorMsg:  "The Person creator field is not allowed",
			},
			ReportedBySpec: []string{spec},
		}
		issues = append(issues, &issue)
	}
	if !foundGoogleCreator {
		issue := types.CreateWrongValueFieldError(
			types.CreatorTool,
			fmt.Sprintf("Organization: %s", googleCreatorOrganization),
			spec,
		)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasGoogleDocumentNamespace(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	// The document namespace should match 'https://spdx.google.com/<uuid>'.
	after, found := strings.CutPrefix(doc.DocumentNamespace, googleDocNamespacePrefix)
	if !found || uuid.Validate(after) != nil {
		issue := types.CreateWrongValueFieldError(
			types.DocumentNamespace,
			fmt.Sprintf("%s<uuid>", googleDocNamespacePrefix),
			spec,
		)
		issues = append(issues, issue)
		return issues
	}
	return issues
}

// Checks the license information fields.
func OtherLicensingInformationFields(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	// License Identifier field
	// Check if it exists at all
	switch {
	case doc.OtherLicenses == nil:
		issue := types.CreateFieldError(types.LicenseIdentifier, spec)
		issues = append(issues, issue)
	case len(doc.OtherLicenses) == 0:
		issue := types.CreateFieldError(types.LicenseIdentifier, spec)
		issues = append(issues, issue)
	default:
		// Check correct formatting
		for i, licenseIDField := range doc.OtherLicenses {
			var licenseName string
			if licenseIDField.LicenseIdentifier == "" {
				licenseName = fmt.Sprintf("License index %d", i)
				issue := types.OtherLicenseError(licenseName, spec, "No LicenseID")
				issues = append(issues, issue)
			}
			if !strings.HasPrefix(licenseIDField.LicenseIdentifier, "LicenseRef-") {
				issue := types.OtherLicenseError(
					licenseName,
					spec,
					"LicenseID should be prefixed with 'LicenseRef-'",
				)
				issues = append(issues, issue)
			}

			// Extracted text
			if !util.IsValidString(licenseIDField.ExtractedText) {
				issue := types.OtherLicenseError(
					licenseName,
					spec,
					"Extracted Text is required",
				)
				issues = append(issues, issue)
			}

			// LicenseCrossReferences
			if len(licenseIDField.LicenseCrossReferences) == 0 {
				issue := types.OtherLicenseError(
					licenseName,
					spec,
					"License Cross Reference is required.",
				)
				issues = append(issues, issue)
			} else {
				for _, cr := range licenseIDField.LicenseCrossReferences {
					if !util.IsValidString(cr) {
						issue := types.OtherLicenseError(
							licenseName,
							spec,
							"Invalid license cross reference. Cannot be '', 'noassert' or 'none'.",
						)
						issues = append(issues, issue)
					}
				}
			}
		}
	}
	return issues
}

func CheckPackageLicenses(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	licenseInfoFromFileValid := func(licenseRef string) bool {
		return licenseRef == common.None || common.ExtractLicenseRefIDString(licenseRef) != nil
	}
	issues := make([]*types.NonConformantField, 0)

	if licenseInfoFromFileValid(sbomPack.PackageLicenseConcluded) {
		return issues
	}
	allLicenseInfoFromFilesValid := true
	for _, licenseFromFile := range sbomPack.PackageLicenseInfoFromFiles {
		allLicenseInfoFromFilesValid = allLicenseInfoFromFilesValid &&
			licenseInfoFromFileValid(licenseFromFile)
	}
	if len(sbomPack.PackageLicenseInfoFromFiles) > 0 && allLicenseInfoFromFilesValid {
		return issues
	}
	issue := &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "licenseError",
			ErrorMsg: "Neither the Concluded License nor the License From Files fields " +
				"contain references to custom license expressions",
		},
		CheckName:      checkName,
		ReportedBySpec: []string{spec},
	}
	issues = append(issues, issue)
	return issues
}

func CheckPackageSupplier(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	supplier := sbomPack.PackageSupplier
	if supplier != nil {
		if supplier.Supplier == common.NoAssertion ||
			(slices.Contains([]string{"Organization", "Person"}, supplier.SupplierType) && supplier.Supplier != "") {
			return issues
		}
	}
	issue := types.MandatoryPackageFieldError(types.
		PackageSupplier, spec)
	issue.CheckName = checkName
	issues = append(issues, issue)
	return issues
}

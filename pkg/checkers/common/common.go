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

package common

/*
Contains checks that multiple specs use
*/

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v2common "github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const NoAssertion = "NOASSERTION"

func CheckOtherLicensingInformationSection(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	licenseIds := map[string]any{}
	for _, licenseInfo := range doc.OtherLicenses {
		// https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#102-extracted-text-field
		// is required
		if licenseInfo.ExtractedText == "" {
			issues = append(issues, types.MandatoryPackageFieldError(types.ExtractedText, spec))
		}

		// https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#101-license-identifier-field
		// is required, needs a specific format, and should be unique.
		if licenseInfo.LicenseIdentifier == "" {
			issues = append(issues, types.MandatoryPackageFieldError(types.LicenseIdentifier, spec))
			continue
		}
		after, found := strings.CutPrefix(licenseInfo.LicenseIdentifier, "LicenseRef-")
		if !found || len(after) == 0 || !IDStringIsConformant(after) {
			issues = append(
				issues,
				types.CreateWronglyFormattedFieldError(types.LicenseIdentifier, spec),
			)
			continue
		}
		if _, found := licenseIds[after]; found {
			issues = append(issues, &types.NonConformantField{
				Error: &types.FieldError{
					ErrorType: "uniqueIdViolation",
					ErrorMsg: fmt.Sprintf(
						"The License Identifier LicenseRef-%s is not unique",
						after,
					),
				},
			})
		}
		licenseIds[after] = struct{}{}
	}
	return issues
}

func SBOMHasSPDXVersion(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.SPDXVersion == "" {
		issue := types.CreateWronglyFormattedFieldError(types.SPDXVersion, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasCorrectDataLicense(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.DataLicense != "CC0-1.0" {
		issue := types.CreateWrongValueFieldError(types.DataLicense, "SPDXRef-DOCUMENT", spec)
		issues = append(issues, issue)
	}
	return issues
}

func CheckCreatedIsConformant(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.CreationInfo == nil {
		issues = append(issues, types.CreateFieldError(types.Created, spec))
		return issues
	}
	// Check that the string is a valid RFC3339 time. However, the RFC allows for
	// a timezone offset other than UTC, which is not allowed by SPDX. This is
	// verified by checking that the last character is 'Z'.
	_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
	if err != nil || !strings.HasSuffix(doc.CreationInfo.Created, "Z") {
		issues = append(issues, WrongDateFormat(doc, spec))
	}
	return issues
}

func SBOMHasCorrectSPDXIdentifier(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.SPDXIdentifier != "DOCUMENT" {
		issue := types.CreateWrongValueFieldError(types.SPDXID, "SPDXRef-DOCUMENT", spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasDocumentName(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.DocumentName == "" {
		issue := types.CreateFieldError(types.DocumentName, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasValidDocumentNamespace(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.DocumentNamespace == "" {
		issue := types.CreateFieldError(types.DocumentNamespace, spec)
		issues = append(issues, issue)
		return issues
	}
	url, err := url.Parse(doc.DocumentNamespace)
	if err != nil {
		issue := types.CreateWronglyFormattedFieldError(types.DocumentNamespace, spec)
		issues = append(issues, issue)
		return issues
	}
	if !url.IsAbs() || strings.Contains(doc.DocumentNamespace, "#") {
		issue := types.CreateWronglyFormattedFieldError(types.DocumentNamespace, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasAtLeastOneCreator(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		issues = append(issues, types.CreateWronglyFormattedFieldError(types.Creator, spec))
	}
	return issues
}

func WrongDateFormat(
	doc *v23.Document,
	spec string,
) *types.NonConformantField {
	errorMsg := fmt.Sprintf("The 'Created' field is formatted incorrectly. "+
		"It is %s. "+
		"The correct format is YYYY-MM-DDThh:mm:ssZ",
		doc.CreationInfo.Created)
	return &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "formatError",
			ErrorMsg:  errorMsg,
		},
		ReportedBySpec: []string{spec},
	}
}

func CheckSPDXID(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if sbomPack.PackageSPDXIdentifier == "" {
		issue := types.MandatoryPackageFieldError(
			types.PackageSPDXIdentifier,
			spec,
		)
		issue.CheckName = checkName
		issues = append(issues, issue)
		return issues
	}
	elID := v2common.RenderElementID(sbomPack.PackageSPDXIdentifier)
	idstring, found := strings.CutPrefix(elID, "SPDXRef-")
	if !found {
		issue := missingSPDXIDPrefix(spec)
		issue.CheckName = checkName
		issues = append(issues, issue)
	} else if !IDStringIsConformant(idstring) {
		issue := wrongSPDXID(spec)
		issue.CheckName = checkName
		issues = append(issues, issue)
	}
	return issues
}

func missingSPDXIDPrefix(
	spec string,
) *types.NonConformantField {
	e := "SPDX Identifier for package %s is non-conformant. " +
		"The format should be SPDXRef-\"[idstring]\""
	return &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "formatError",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

func IDStringIsConformant(idstring string) bool {
	// This function is tested via TestSPDXTopLevelChecks and TestSPDXPkgResults.
	charIsNotAllowed := func(c rune) bool {
		return c != '.' && c != '-' && !unicode.IsLetter(c) && !unicode.IsDigit(c)
	}
	return !strings.ContainsFunc(idstring, charIsNotAllowed)
}

func wrongSPDXID(
	spec string,
) *types.NonConformantField {
	e := "SPDX Identifier is non-conformant. " +
		"It should have letters, numbers, \".\" and/or \"-\""
	return &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "formatError",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

// Checks that the SBOM has a Name.
func MustHaveName(
	sbomPackage *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if !util.IsValidString(sbomPackage.PackageName) {
		issue := types.MandatoryPackageFieldError(types.PackageName, spec)
		issue.CheckName = checkName
		issues = append(issues, issue)
	}
	return issues
}

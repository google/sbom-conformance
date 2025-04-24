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
	"strings"
	"time"
	"unicode"

	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v2common "github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const NoAssertion = "NOASSERTION"

func SBOMHasSPDXVersion(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if !util.IsValidString(doc.SPDXVersion) {
		issue := types.CreateFieldError(types.SPDXVersion, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasDataLicense(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if !util.IsValidString(doc.DataLicense) {
		issue := types.CreateFieldError(types.DataLicense, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasSPDXIdentifier(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.SPDXIdentifier == "" {
		issue := types.CreateFieldError(types.SPDXID, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasDocumentName(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if !util.IsValidString(doc.DocumentName) {
		issue := types.CreateFieldError(types.DocumentNamespace, spec)
		issues = append(issues, issue)
	}
	return issues
}

func SBOMHasDocumentNamespace(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if !util.IsValidString(doc.DocumentNamespace) {
		issue := types.CreateFieldError(types.DocumentNamespace, spec)
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
		issues = append(issues, types.CreateFieldError(types.Creator, spec))
	}
	return issues
}

func wrongDateFormat(
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

func wrongCreatorName(
	creator, spec string,
) *types.NonConformantField {
	e := fmt.Sprintf("Creator organization is '%s', "+
		"but should always be 'Google LLC'.",
		creator)
	return &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "formatError",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

func wrongCreatorType(spec string) *types.NonConformantField {
	e := fmt.Sprintf("Creator type is 'Person', " +
		"but can only be 'Organization' or 'Tool'.")
	return &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "formatError",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

// Checks the SBOMs creation info fields.
func SBOMHasCorrectCreationInfo(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.CreationInfo == nil {
		issue := types.CreateFieldError(types.Created, spec)
		issues = append(issues, issue)
	} else {
		if !util.IsValidString(doc.CreationInfo.Created) {
			issue := types.CreateFieldError(types.Created, spec)
			issues = append(issues, issue)
		}
		_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
		if err != nil {
			issue := wrongDateFormat(doc, spec)
			issues = append(issues, issue)
		}
		for _, creator := range doc.CreationInfo.Creators {
			switch creator.CreatorType {
			case "Organization":
				if creator.Creator != "Google LLC" {
					issue := wrongCreatorName(creator.Creator, spec)
					issues = append(issues, issue)
				}
			case "Person":
				issue := wrongCreatorType(spec)
				issues = append(issues, issue)
			}
		}
	}
	return issues
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

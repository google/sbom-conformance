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

package spdx

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/sbom-conformance/pkg/checkers/common"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// Matches strings like "Organization: foo (foo@bar.com)". The email is captured.
// The spec isn't very clear, but we interpret it to allow
// "Organization: foo (inc) (email@domain.com)". In other words, the email is the
// last parenthesis group.
var creatorEmail *regexp.Regexp = regexp.MustCompile(`.+?\ \(([^\(\)]*?)\)$`)

func CheckCreatorIsConformant(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		issues = append(issues, types.CreateFieldError(types.Creator, spec))
		return issues
	}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.Creator == "" {
			issues = append(issues, types.CreateFieldError(types.Creator, spec))
			continue
		}
		switch creator.CreatorType {
		case "Tool":
			tool, version, found := strings.Cut(creator.Creator, "-")
			if !found || version == "" || tool == "" {
				issues = append(issues, types.CreateWronglyFormattedFieldError(types.Creator, spec))
			}
		case "Person", "Organization":
			matches := creatorEmail.FindStringSubmatch(creator.Creator)
			// an email is not required, and we allow '()'
			if len(matches) <= 1 || matches[1] == "" {
				continue
			}
			if _, err := mail.ParseAddress(matches[1]); err != nil {
				issues = append(issues, types.CreateWronglyFormattedFieldError(types.Creator, spec))
			}
		default:
			issues = append(issues, types.CreateFieldError(types.Creator, spec))
		}
	}
	return issues
}

func CheckDownloadLocation(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if sbomPack.PackageDownloadLocation == "" {
		issue := types.MandatoryPackageFieldError(
			types.PackageDownloadLocation, spec,
		)
		issue.CheckName = checkName
		issues = append(issues, issue)
	}
	return issues
}

func CheckFilesAnalyzed(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if sbomPack.PackageVerificationCode != nil && !sbomPack.FilesAnalyzed {
		issues = append(issues, &types.NonConformantField{
			Error: &types.FieldError{
				ErrorType: "wrongValue",
				ErrorMsg:  "filesAnalyzed must be true",
			},
			CheckName:      checkName,
			ReportedBySpec: []string{spec},
		})
	}
	return issues
}

func CheckOtherLicensingInformationSection(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if doc.OtherLicenses == nil {
		return issues
	}
	licenseIds := map[string]any{}
	// These licenses should only be present if they are not already on the SPDX
	// license list, but this is not verified.
	for _, licenseInfo := range doc.OtherLicenses {
		// https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#101-license-identifier-field
		// is required
		if licenseInfo.LicenseIdentifier == "" {
			issues = append(issues, types.MandatoryPackageFieldError(types.LicenseIdentifier, spec))
		}
		after, found := strings.CutPrefix(licenseInfo.LicenseIdentifier, "LicenseRef-")
		if !found || len(after) == 0 || !common.IDStringIsConformant(after) {
			issues = append(
				issues,
				types.CreateWronglyFormattedFieldError(types.LicenseIdentifier, spec),
			)
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

		// https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#102-extracted-text-field
		// is required
		if licenseInfo.ExtractedText == "" {
			issues = append(issues, types.MandatoryPackageFieldError(types.ExtractedText, spec))
		}
	}
	return issues
}

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

	types "github.com/google/sbom-conformance/pkg/checkers/types"
	spdxCommon "github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// Matches strings like "Organization: foo (foo@bar.com)". The email is captured.
// The spec isn't very clear, but we interpret it to allow
// "Organization: foo (inc) (email@domain.com)". In other words, the email is the
// last parenthesis group.
var creatorEmail *regexp.Regexp = regexp.MustCompile(`.+?\ \(([^\(\)]*?)\)$`)

func CheckUniqueSPDXIdentifier(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	spdxIDs := map[string]any{}
	for _, pkg := range doc.Packages {
		spdxID := spdxCommon.RenderElementID(pkg.PackageSPDXIdentifier)
		if _, found := spdxIDs[spdxID]; found {
			issues = append(issues, &types.NonConformantField{
				Error: &types.FieldError{
					ErrorType: "uniqueIdViolation",
					ErrorMsg:  fmt.Sprintf("The Package SPDX Identifier %s is not unique", spdxID),
				},
			})
		}
		spdxIDs[spdxID] = struct{}{}
	}
	return issues
}

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

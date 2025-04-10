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

package eo

import (
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func checkRelationshipsFields(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	for _, relationship := range doc.Relationships {
		// Check the relationship type
		if !util.IsValidString(relationship.Relationship) {
			issue := types.CreateWronglyFormattedFieldError(types.RelationshipType,
				spec)
			issues = append(issues, issue)
		}
	}
	return issues
}

func MustHaveSupplier(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if sbomPack.PackageSupplier == nil || sbomPack.PackageSupplier.Supplier == "" {
		issue := missingPackageSupplier(spec)
		issue.CheckName = checkName
		issues = append(issues, issue)
	}
	return issues
}

func MustHaveValidVersion(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if !util.IsValidString(sbomPack.PackageVersion) {
		issue := types.MandatoryPackageFieldError("PackageVersion",
			spec)
		issue.CheckName = checkName
		issues = append(issues, issue)
	}
	return issues
}

func MustHaveExternalReferences(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if len(sbomPack.PackageExternalReferences) == 0 {
		issue := types.MandatoryPackageFieldError(
			types.PackageExternalReferences,
			spec,
		)
		issue.CheckName = checkName
		issues = append(issues, issue)
	}
	return issues
}

func missingPackageSupplier(spec string) *types.NonConformantField {
	e := "The supplier field is missing"
	return &types.NonConformantField{
		Error: &types.FieldError{
			ErrorType: "missingField",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

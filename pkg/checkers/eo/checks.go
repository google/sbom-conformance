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
	"fmt"

	"github.com/google/sbom-conformance/pkg/checkers/common"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func checkPackagesHaveRelationships(
	doc *v23.Document,
	spec string,
) []*types.NonConformantField {
	// packagesInRelationships maps spdxIDs to whether a relationship exists for
	// that package
	packagesInRelationships := map[string]bool{}
	for _, pkg := range doc.Packages {
		packagesInRelationships[string(pkg.PackageSPDXIdentifier)] = false
	}
	for _, relationship := range doc.Relationships {
		if relationship == nil {
			// untested; not clear how to cause this
			continue
		}

		// If a package reference is NONE or is NOASSERTION, then ElementRefID will
		// be empty and SpecialID will be NONE or NOASSERTION. We prefer to handle
		// these possibilities as a single value.
		refA := string(relationship.RefA.ElementRefID)
		if specialID := relationship.RefA.SpecialID; specialID != "" {
			refA = specialID
		}
		refB := string(relationship.RefB.ElementRefID)
		if specialID := relationship.RefB.SpecialID; specialID != "" {
			refB = specialID
		}

		// the relationship shouldn't count if both sides of the relationship are
		// the same
		if refA == refB {
			continue
		}

		if refA == common.NoAssertion || refB == common.NoAssertion {
			continue
		}

		// DocumentRefID is empty if the reference is an element of the current SBOM.
		// Only packages defined in the current SBOM are present in
		// packagesInRelationships, so there's no need to check packagesInRelationships
		// if DocumentRefID is not empty.
		if relationship.RefA.DocumentRefID == "" {
			// this might add NONE to the map, but it doesn't matter
			packagesInRelationships[refA] = true
		}
		if relationship.RefB.DocumentRefID == "" {
			// this might add NONE to the map, but it doesn't matter
			packagesInRelationships[refB] = true
		}
	}
	var packagesMissingRelationships int
	for _, inRelationship := range packagesInRelationships {
		if !inRelationship {
			packagesMissingRelationships++
		}
	}

	if packagesMissingRelationships == 0 {
		return nil
	}
	return []*types.NonConformantField{{
		Error: &types.FieldError{
			ErrorType: "missingRelationship",
			ErrorMsg: fmt.Sprintf(
				"%v packages are not in any relationships",
				packagesMissingRelationships,
			),
		},
		ReportedBySpec: []string{spec},
	}}
}

func MustHaveTimestamp(sbom *v23.Document, spec string) []*types.NonConformantField {
	if sbom.CreationInfo == nil || sbom.CreationInfo.Created == "" {
		return []*types.NonConformantField{types.MandatoryPackageFieldError("Created", spec)}
	}
	return nil
}

func MustHaveSupplier(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if sbomPack.PackageSupplier == nil ||
		sbomPack.PackageSupplier.Supplier == "" ||
		sbomPack.PackageSupplier.Supplier == common.NoAssertion {
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

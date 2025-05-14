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
	"github.com/google/sbom-conformance/pkg/checkers/common"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const (
	// top-level checks.
	HasAtLeastOneCreator = "Check that the SBOM has at least one creator"
	HasTimestamp         = "Check that the SBOM has a timestamp"
	HasRelationships     = "Check that each SBOM package has a relationship"

	// package-level checks.
	PackageHasName              = "Check that SBOM packages have a name"
	PackageHasValidVersion      = "Check that SBOM packages have a valid version"
	PackageHasSupplier          = "Check that the package has a supplier"
	PackageHasExternalReference = "Check that SBOM packages have external references"
)

type EOChecker struct {
	Name           string                      `json:"name"`
	TopLevelChecks []*types.TopLevelCheck      `json:"topLevelChecks"`
	PkgLevelChecks []*types.PackageLevelCheck  `json:"pkgLevelChecks"`
	Issues         []*types.NonConformantField `json:"issues"`

	// Contains results of the packages in the SBOM.
	PkgResults []*types.PkgResult `json:"pkgResults"`
}

func (eoChecker *EOChecker) InitChecks() {
	topLevelChecks := []*types.TopLevelCheck{
		{
			Name: HasAtLeastOneCreator,
			Impl: common.SBOMHasAtLeastOneCreator,
		},
		{
			Name: HasTimestamp,
			Impl: MustHaveTimestamp,
		},
		{
			Name: HasRelationships,
			Impl: checkPackagesHaveRelationships,
		},
	}
	eoChecker.TopLevelChecks = topLevelChecks

	packageLevelChecks := []*types.PackageLevelCheck{
		{
			Name: PackageHasName,
			Impl: common.MustHaveName,
		},
		{
			Name: PackageHasValidVersion,
			Impl: MustHaveValidVersion,
		},
		{
			Name: PackageHasSupplier,
			Impl: MustHaveSupplier,
		},
		{
			Name: PackageHasExternalReference,
			Impl: MustHaveExternalReferences,
		},
	}
	eoChecker.PkgLevelChecks = packageLevelChecks
}

func (eoChecker *EOChecker) RunTopLevelChecks(doc *v23.Document) {
	for _, check := range eoChecker.TopLevelChecks {
		issues := check.Impl(doc, types.EO)
		for _, issue := range issues {
			issue.CheckName = check.Name
		}
		eoChecker.Issues = append(eoChecker.Issues, issues...)
	}
}

func (eoChecker *EOChecker) GetIssues() []*types.NonConformantField {
	return eoChecker.Issues
}

// Returns the spdxCheckers checks as strings.
func (eoChecker *EOChecker) GetChecks() []string {
	allChecks := make([]string, 0)
	for _, topLevelCheck := range eoChecker.TopLevelChecks {
		allChecks = append(allChecks, topLevelCheck.Name)
	}
	for _, pkgLevelCheck := range eoChecker.PkgLevelChecks {
		allChecks = append(allChecks, pkgLevelCheck.Name)
	}
	return allChecks
}

func (eoChecker *EOChecker) GetTopLevelChecks() []string {
	checks := make([]string, 0)
	for _, topLevelCheck := range eoChecker.TopLevelChecks {
		checks = append(checks, topLevelCheck.Name)
	}
	return checks
}

func (eoChecker *EOChecker) GetPackageLevelChecks() []string {
	checks := make([]string, 0)
	for _, topLevelCheck := range eoChecker.PkgLevelChecks {
		checks = append(checks, topLevelCheck.Name)
	}
	return checks
}

func (eoChecker *EOChecker) GetPackages() []*types.PkgResult {
	return eoChecker.PkgResults
}

func (eoChecker *EOChecker) SpecName() string {
	return eoChecker.Name
}

// Checks the SBOMs package fields.
func (eoChecker *EOChecker) CheckPackages(doc *v23.Document) {
	eoChecker.PkgResults = util.RunPkgLevelChecks(doc, eoChecker.PkgLevelChecks, eoChecker.Name)
}

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
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

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

func CheckVerificationCode(
	sbomPack *v23.Package,
	spec, checkName string,
) []*types.NonConformantField {
	issues := make([]*types.NonConformantField, 0)
	if sbomPack.FilesAnalyzed {
		if sbomPack.PackageVerificationCode == nil ||
			!util.IsValidString(sbomPack.PackageVerificationCode.Value) {
			issue := types.MandatoryPackageFieldError(
				types.PackageVerificationCode, spec,
			)
			issue.CheckName = checkName
			issues = append(issues, issue)
		}
	}
	return issues
}

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

package types

// in sbom-conformance.
import (
	"fmt"

	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

var (
	// Conformance specs.
	Google = "Google"
	EO     = "EO"
	SPDX   = "SPDX"

	// Required fields.
	SPDXVersion                 = "SPDX Version"
	DataLicense                 = "Data License"
	SPDXID                      = "SPDX ID"
	DocumentNamespace           = "Document Namespace"
	DocumentName                = "Document Name"
	Creator                     = "Creator"
	CreatorTool                 = "Creator Tool"
	CreatorOrganization         = "Creator Organization"
	Created                     = "Created"
	LicenseIdentifier           = "License Identifier"
	ExtractedText               = "Extracted Text"
	LicenseCrossReferences      = "LicenseCrossReferences"
	PackageName                 = "PackageName"
	PackageSPDXIdentifier       = "PackageSPDXIdentifier"
	PackageVersion              = "PackageVersion"
	PackageDownloadLocation     = "PackageDownloadLocation"
	PackageVerificationCode     = "PackageVerificationCode"
	PackageLicenseConcluded     = "PackageLicenseConcluded"
	PackageFilesAnalyzed        = "PackageFilesAnalyzed"
	PackageLicenseInfoFromFiles = "PackageLicenseInfoFromFiles"
	PackageExternalReferences   = "PackageExternalReferences"
	PackageSupplier             = "PackageSupplier"
	RelationshipType            = "Relationship Type"
)

type TopLevelCheck struct {
	Impl func(doc *v23.Document, spec string) []*NonConformantField
	Name string `json:"name"`
}

type PackageLevelCheck struct {
	Impl func(pack *v23.Package, spec, checkName string) []*NonConformantField
	Name string `json:"name"`
}

type FieldError struct {
	ErrorType string `json:"errorType"` // TODO: Could probably be an enum
	ErrorMsg  string `json:"errorMsg"`
}

type NonConformantField struct {
	Error          *FieldError `json:"error"`
	CheckName      string      `json:"checkName,omitempty"`
	ReportedBySpec []string    `json:"reportedBySpec"`
}

type Package struct {
	Name   string `json:"name,omitempty"`   // Package name
	SpdxID string `json:"spdxId,omitempty"` // Package ID
}

type PkgResult struct {
	Package *Package              `json:"package,omitempty"`
	Errors  []*NonConformantField `json:"errors,omitempty"`
}

func CreateWrongValueFieldError(field, expectedValue, spec string) *NonConformantField {
	issue := &NonConformantField{
		Error: &FieldError{
			ErrorType: "wrongValue",
			ErrorMsg:  fmt.Sprintf("The field %q should be %q", field, expectedValue),
		},
		ReportedBySpec: []string{spec},
	}
	return issue
}

func CreateFieldError(field, spec string) *NonConformantField {
	issue := &NonConformantField{
		Error: &FieldError{
			ErrorType: "missingField",
			ErrorMsg:  fmt.Sprintf("SBOM has no %s field", field),
		},
		ReportedBySpec: []string{spec},
	}
	return issue
}

func OtherLicenseError(
	licenseName, spec, err string,
) *NonConformantField {
	e := fmt.Sprintf(
		"SBOM Other License %s is formatted incorrectly: %s",
		licenseName, err,
	)
	return &NonConformantField{
		Error: &FieldError{
			ErrorType: "formatError",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

func CreateWronglyFormattedFieldError(
	field, spec string,
) *NonConformantField {
	e := fmt.Sprintf("SBOM field %s is formatted incorrectly", field)
	return &NonConformantField{
		Error: &FieldError{
			ErrorType: "formatError",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}
}

func MandatoryPackageFieldError(
	field, spec string,
) *NonConformantField {
	e := fmt.Sprintf("Has no %s field", field)
	issue := &NonConformantField{
		Error: &FieldError{
			ErrorType: "missingField",
			ErrorMsg:  e,
		},
		ReportedBySpec: []string{spec},
	}

	return issue
}

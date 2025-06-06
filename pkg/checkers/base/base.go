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

package base

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/google/sbom-conformance/pkg/checkers/eo"
	"github.com/google/sbom-conformance/pkg/checkers/google"
	"github.com/google/sbom-conformance/pkg/checkers/spdx"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	jsonParsing "github.com/spdx/tools-golang/json"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/yaml"
)

var (
	errNewChecker   = errors.New("the checker has no spec(s). BaseChecker needs at least one spec")
	ErrSPDXVersion  = errors.New("the SBOM is not SPDX-2.3")
	ErrParseFailure = errors.New("the SBOM could not be parsed")
)

// The interface for space checkers.
type SpecChecker interface {
	InitChecks()

	// RunTopLevelChecks runs the checkers's top-level checks. The results can be
	// be retrieved with GetIssues().
	RunTopLevelChecks(doc *v23.Document)
	CheckPackages(doc *v23.Document)

	GetIssues() []*types.NonConformantField
	GetPackages() []*types.PkgResult
	SpecName() string
	GetChecks() []string
	GetTopLevelChecks() []string
	GetPackageLevelChecks() []string
}

type BaseChecker struct {
	ErrsAndPacks    map[string][]string       `json:"errsAndPacks"`
	Document        *v23.Document             `json:"document"`
	SpecCheckers    []SpecChecker             `json:"specCheckers"`
	TopLevelResults []*util.DeduplicatedIssue `json:"topLevelResults"`
	PkgResults      []*types.PkgResult        `json:"pkgResults"`
}

type ErrPack struct{}

func NewChecker(options ...func(*BaseChecker)) (*BaseChecker, error) {
	checker := &BaseChecker{
		SpecCheckers:    make([]SpecChecker, 0),
		TopLevelResults: make([]*util.DeduplicatedIssue, 0),
		PkgResults:      make([]*types.PkgResult, 0),
	}
	for _, o := range options {
		o(checker)
	}
	if len(checker.SpecCheckers) == 0 {
		return nil, errNewChecker
	}
	return checker, nil
}

// Initializes the BaseChecker with the input SBOM. After this call, RunChecks()
// can be called. Existing results stored in the BaseChecker are not reset.
func (checker *BaseChecker) SetSPDXDocument(sbom *v23.Document) {
	checker.Document = sbom
}

// Initializes the BaseChecker with the input SBOM. After this call, RunChecks()
// can be called. Existing results stored in the BaseChecker are not reset.
//
// An error will be returned if the input is not SPDX 2.3. Use
// errors.Is(err, base.ErrSPDXVersion) to check for this.
func (checker *BaseChecker) SetSBOM(sbom io.Reader) error {
	buf := bytes.Buffer{}
	_, err := buf.ReadFrom(sbom)
	if err != nil {
		return fmt.Errorf("error reading from the sbom: %w", err)
	}
	doc, err := parseSBOM(buf.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrParseFailure, err) //nolint:all
	}
	if doc.SPDXVersion != "SPDX-2.3" {
		return fmt.Errorf("%w. The SPDX version is: %v", ErrSPDXVersion, doc.SPDXVersion)
	}
	checker.Document = doc
	return nil
}

// parseSBOM parses the input bytes into the SPDX representation.
//
// This function is used instead of spdx library json.ReadInto in order to avoid
// converting the SBOM to other SPDX versions and because the bytes are needed
// to extract the actual SPDX version.
func parseSBOM(sbom []byte) (*v23.Document, error) {
	var doc v23.Document
	// error is wrapped in SetSBOM
	return &doc, json.Unmarshal(sbom, &doc) //nolint:wrapcheck
}

func WithSBOMFile(sbomPath string) func(*BaseChecker) {
	return func(checker *BaseChecker) {
		doc := &v23.Document{}
		file, err := os.Open(sbomPath)
		if err != nil {
			panic(fmt.Errorf("error opening File: %w", err))
		}
		defer file.Close()

		err = jsonParsing.ReadInto(file, doc)
		if err == nil {
			checker.Document = doc
			return
		}

		err = tagvalue.ReadInto(file, doc)
		if err == nil {
			checker.Document = doc
			return
		}

		err = yaml.ReadInto(file, doc)
		if err == nil {
			checker.Document = doc
			return
		}
		panic("Could not parse SBOM file")
	}
}

func WithGoogleChecker() func(*BaseChecker) {
	return func(checker *BaseChecker) {
		checker.AddGoogleSpec()
	}
}

func WithEOChecker() func(*BaseChecker) {
	return func(checker *BaseChecker) {
		checker.AddEOSpec()
	}
}

func WithSPDXChecker() func(*BaseChecker) {
	return func(checker *BaseChecker) {
		checker.AddSPDXSpec()
	}
}

func (checker *BaseChecker) AddSpec(spec SpecChecker) {
	checker.SpecCheckers = append(checker.SpecCheckers, spec)
}

func (checker *BaseChecker) ResetResults(spec SpecChecker) {
	checker.TopLevelResults = make([]*util.DeduplicatedIssue, 0)
	checker.PkgResults = make([]*types.PkgResult, 0)
}

func (checker *BaseChecker) countFailedPackages(
	checkName string,
	pkgResults []*types.PkgResult,
) int {
	numberOfFailedPkgs := 0
	for _, issue := range pkgResults {
		for _, confError := range issue.Errors {
			if confError.CheckName == checkName {
				numberOfFailedPkgs += 1
			}
		}
	}
	return numberOfFailedPkgs
}

func (checker *BaseChecker) checkIsTopLvl(checkName string) bool {
	for _, specChecker := range checker.SpecCheckers {
		for _, topLvlCheck := range specChecker.GetTopLevelChecks() {
			if topLvlCheck == checkName {
				return true
			}
		}
	}
	return false
}

func (checker *BaseChecker) checkIsPkg(checkName string) bool {
	for _, specChecker := range checker.SpecCheckers {
		for _, topLvlCheck := range specChecker.GetPackageLevelChecks() {
			if topLvlCheck == checkName {
				return true
			}
		}
	}
	return false
}

// checksRunWithSpecification returns a map from the name of checks to the specifications that
// include them. If the input function is provided, a check will only be included if
// the function returns true when called on the check name. It is expected that
// the checks have already been run.
func (checker *BaseChecker) checksRunWithSpecification(
	filterFunc func(string) bool,
) map[string][]string {
	checksToSpecifications := map[string][]string{}
	for _, specChecker := range checker.SpecCheckers {
		for _, check := range specChecker.GetChecks() {
			if !filterFunc(check) {
				continue
			}
			checksToSpecifications[check] = append(
				checksToSpecifications[check],
				specChecker.SpecName(),
			)
		}
	}
	return checksToSpecifications
}

// GetTopLevelChecks returns the results of all the top-level checks that have
// been run.
func (checker *BaseChecker) GetTopLevelChecks() []*types.TopLevelCheckResult {
	checksToSpecifications := checker.checksRunWithSpecification(checker.checkIsTopLvl)
	var result []*types.TopLevelCheckResult
	for checkName, specs := range checksToSpecifications {
		topLevelCheckResult := types.TopLevelCheckResult{
			Name:   checkName,
			Passed: true,
			Specs:  specs,
		}
		// checker.TopLevelResults only contains checks that have failed.
		for _, res := range checker.TopLevelResults {
			if res.CheckName == checkName {
				topLevelCheckResult.Passed = false
			}
		}
		result = append(result, &topLevelCheckResult)
	}
	return result
}

// GetPackageLevelChecks returns the results of all the package-level checks
// that have been run.
func (checker *BaseChecker) GetPackageLevelChecks() []*types.PackageLevelCheckResult {
	checksToSpecifications := checker.checksRunWithSpecification(checker.checkIsPkg)
	var result []*types.PackageLevelCheckResult
	for checkName, specs := range checksToSpecifications {
		topLevelCheckResult := types.PackageLevelCheckResult{
			Name:           checkName,
			FailedPackages: checker.countFailedPackages(checkName, checker.PkgResults),
			Specs:          specs,
		}
		result = append(result, &topLevelCheckResult)
	}
	return result
}

// Creates a spec summary of all the specs in the BaseChecker.
func (checker *BaseChecker) SpecSummaries() map[string]*types.SpecSummary {
	// Create a map where the key is the spec name
	// and the value is a summary of that specs findings.
	summaries := make(map[string]*types.SpecSummary)
	for _, specChecker := range checker.SpecCheckers {
		specName := specChecker.SpecName()
		_, ok := summaries[specName]
		if !ok {
			// Set default values
			summaries[specChecker.SpecName()] = &types.SpecSummary{}
			summaries[specName].TotalChecks = len(specChecker.GetChecks())
		}

		// Count the passed
		numberOfFailedChecks := checker.countFailedChecks(summaries, specChecker)
		summaries[specName].PassedChecks = len(specChecker.GetChecks()) - numberOfFailedChecks
		summaries[specName].Conformant = numberOfFailedChecks == 0
	}
	return summaries
}

func (checker *BaseChecker) countFailedChecks(
	summaries map[string]*types.SpecSummary, specChecker SpecChecker,
) int {
	// Create an intermediary map that records
	// the failed checks. We use this as a way
	// to avoid counting double.
	// "true" means that the check has failed.
	numberOfFailedChecks := 0
	failedChecks := make(map[string]bool)
	for _, check := range specChecker.GetChecks() {
		if _, ok := failedChecks[check]; !ok {
			failedChecks[check] = false
		}
		if failedChecks[check] {
			continue
		}

		if checker.isFailedPkgLevelCheck(check) {
			if !failedChecks[check] {
				failedChecks[check] = true
				numberOfFailedChecks += 1
			}
		}
		if checker.isFailedTopLevelCheck(check) {
			if !failedChecks[check] {
				failedChecks[check] = true
				numberOfFailedChecks += 1
			}
		}
	}
	return numberOfFailedChecks
}

func (checker *BaseChecker) isFailedPkgLevelCheck(checkName string) bool {
	for _, issue := range checker.PkgResults {
		for _, confError := range issue.Errors {
			if confError.CheckName == checkName {
				return true
			}
		}
	}
	return false
}

func (checker *BaseChecker) isFailedTopLevelCheck(checkName string) bool {
	for _, issue := range checker.TopLevelResults {
		if issue.CheckName == checkName {
			return true
		}
	}
	return false
}

func (checker *BaseChecker) TextSummary() string {
	var initialStringBuilder strings.Builder
	initialStringBuilder.WriteString("Summary:\n")
	sbWithTab := util.StringBuilderWithPrefixAndSuffix(&initialStringBuilder, "\t", "\n")

	// Summary
	sbWithTab.Writef(
		"Analyzed an SBOM with %d package(s). %d top-level conformance check(s)"+
			" failed. %d package(s) had at least one failing conformance check.\n",
		checker.NumberOfSBOMPackages(),
		len(checker.TopLevelResults),
		checker.NumberOfSBOMPackages()-checker.NumberOfCompliantPackages(),
	)
	for spec, specSummary := range checker.SpecSummaries() {
		status := "failed"
		if specSummary.Conformant {
			status = "passed"
		}
		sbWithTab.Writef(
			"The %s spec %v. %v/%v checks passed.",
			spec,
			status,
			specSummary.PassedChecks,
			specSummary.TotalChecks,
		)
	}

	// Enumerate the failed top-level checks.
	if len(checker.TopLevelResults) > 0 {
		initialStringBuilder.WriteString("\n")
		sbWithTab.Writef("Top-level conformance issues:")
		topLevelIssues := make([]string, 0)
		for _, issue := range checker.TopLevelResults {
			issue := fmt.Sprintf("%s. %s",
				issue.ErrorMessage,
				issue.NonConformantWithSpecs)
			topLevelIssues = append(topLevelIssues, issue)
		}
		// Sort to make the slice deterministic (which is necessary for testing)
		slices.Sort(topLevelIssues)
		sbWithDash := util.StringBuilderWithPrefixAndSuffix(&initialStringBuilder, "\t- ", "\n")
		for _, topLevelIssue := range topLevelIssues {
			sbWithDash.Writef("%s", topLevelIssue)
		}
	}

	// Enumerate the failed package-level checks.
	if len(checker.ErrsAndPacks) > 0 {
		initialStringBuilder.WriteString("\n")
		sbWithTab.Writef("Conformance issues in packages:")
		pkgLevelIssues := make([]string, 0)
		for e, p := range checker.ErrsAndPacks {
			var packageString string
			if checker.NumberOfSBOMPackages() > 1 {
				packageString = "packages"
			} else {
				packageString = "package"
			}
			issue := fmt.Sprintf("%s: %d/%d %s failed.",
				e,
				len(p),
				checker.NumberOfSBOMPackages(),
				packageString)
			pkgLevelIssues = append(pkgLevelIssues, issue)
		}
		slices.Sort(pkgLevelIssues)
		sbWithDash := util.StringBuilderWithPrefixAndSuffix(&initialStringBuilder, "\t- ", "\n")
		for _, pkgLevelIssue := range pkgLevelIssues {
			sbWithDash.Writef("%s", pkgLevelIssue)
		}
	}
	return initialStringBuilder.String()
}

// Checks all specs.
func (checker *BaseChecker) Results() *types.Output {
	textSummary := checker.TextSummary()
	failedSBOMPackages := checker.NumberOfSBOMPackages() - checker.NumberOfCompliantPackages()
	summary := &types.Summary{
		TotalSBOMPackages:  checker.NumberOfSBOMPackages(),
		FailedSBOMPackages: failedSBOMPackages,
		SpecSummaries:      checker.SpecSummaries(),
	}
	pkgResults := checker.PkgResults
	errsAndPacks := checker.ErrsAndPacks
	return &types.Output{
		TextSummary:        textSummary,
		Summary:            summary,
		TopLevelChecks:     checker.GetTopLevelChecks(),
		PackageLevelChecks: checker.GetPackageLevelChecks(),
		PkgResults:         pkgResults,
		ErrsAndPacks:       errsAndPacks,
	}
}

// Checks all specs.
func (checker *BaseChecker) RunChecks() {
	checker.runTopLevelChecks()
	checker.runPackageChecks()
}

// Checks all specs.
func (checker *BaseChecker) runTopLevelChecks() {
	doc := checker.Document
	tmpTopLevelResults := make([]*types.NonConformantField, 0)
	for _, specChecker := range checker.SpecCheckers {
		specChecker.RunTopLevelChecks(doc)
		tmpTopLevelResults = append(tmpTopLevelResults, specChecker.GetIssues()...)
	}
	checker.TopLevelResults = util.DeduplicateIssues(tmpTopLevelResults)
}

// Checks all packages against the specs in the BaseChecker.
// Prior to this, the user must have added the specs they'd like
// to check.
func (checker *BaseChecker) runPackageChecks() {
	doc := checker.Document
	pkgResults := make([]*types.PkgResult, 0)
	for _, specChecker := range checker.SpecCheckers {
		specChecker.CheckPackages(doc)
		pkgResults = append(pkgResults, specChecker.GetPackages()...)
	}

	mergedPkgsResults := mergePkgResults(pkgResults)

	checker.ErrsAndPacks = createErrAndPkgMap(mergedPkgsResults)

	packageResultsNoDuplicates := deduplicatePackageResults(mergedPkgsResults)
	checker.PkgResults = packageResultsNoDuplicates
}

func (checker *BaseChecker) AddGoogleSpec() {
	googleChecker := &google.GoogleChecker{
		Name:   types.Google,
		Issues: make([]*types.NonConformantField, 0),
	}
	googleChecker.InitChecks()
	checker.SpecCheckers = append(checker.SpecCheckers, googleChecker)
}

func (checker *BaseChecker) AddEOSpec() {
	eoChecker := &eo.EOChecker{
		Name:   types.EO,
		Issues: make([]*types.NonConformantField, 0),
	}
	eoChecker.InitChecks()
	checker.SpecCheckers = append(checker.SpecCheckers, eoChecker)
}

func (checker *BaseChecker) AddSPDXSpec() {
	spdxChecker := &spdx.SPDXChecker{
		Name:   types.SPDX,
		Issues: make([]*types.NonConformantField, 0),
	}
	spdxChecker.InitChecks()
	checker.SpecCheckers = append(checker.SpecCheckers, spdxChecker)
}

// Create map of errors and the packages that have that
// key: error, value: package names with this error.
func createErrAndPkgMap(mergedPacks []*types.PkgResult) map[string][]string {
	errsAndPacks := make(map[string][]string)
	for _, pack := range mergedPacks {
		var packageName string
		switch {
		case pack.Package.Name != "":
			packageName = pack.Package.Name
		default:
			packageName = pack.Package.SpdxID
		}
		for _, e := range pack.Errors {
			if _, ok := errsAndPacks[e.Error.ErrorMsg]; !ok {
				errsAndPacks[e.Error.ErrorMsg] = make([]string, 0)
			}
			if !slices.Contains(errsAndPacks[e.Error.ErrorMsg], packageName) {
				errsAndPacks[e.Error.ErrorMsg] = append(errsAndPacks[e.Error.ErrorMsg],
					packageName)
			}
		}
	}
	return errsAndPacks
}

func resultForSamePackage(pkg1, pkg2 *types.PkgResult) bool {
	if pkg1.Package.SpdxID == "" && pkg2.Package.SpdxID == "" {
		return pkg1.Package.Name == pkg2.Package.Name
	}
	return pkg1.Package.SpdxID == pkg2.Package.SpdxID
}

func mergePkgResults(packs []*types.PkgResult) []*types.PkgResult {
	mergedPacks := make([]*types.PkgResult, 0)
	for _, pack := range packs {
		// Check if we have already merged this package
		haveMerged := false
		for _, mergedPack := range mergedPacks {
			if resultForSamePackage(mergedPack, pack) {
				haveMerged = true
			}
		}
		if haveMerged {
			continue
		}

		newPackage := &types.PkgResult{
			Package: pack.Package,
		}

		// Add all errors for this package
		for _, pack2 := range packs {
			if resultForSamePackage(pack, pack2) {
				newPackage.Errors = append(newPackage.Errors, pack2.Errors...)
			}
		}
		mergedPacks = append(mergedPacks, newPackage)
	}
	return mergedPacks
}

// Deduplicates a list of package results that can have duplicate
// errors. The duplication will be from multiple specs reporting
// identical issues in an SBOM. deduplicatePackageResults removes
// duplicates and instead puts all the specs that reported identical
// issues into a list for the deduplicated error.
func deduplicatePackageResults(mergedPacks []*types.PkgResult) []*types.PkgResult {
	packsNoDupes := make([]*types.PkgResult, 0)
	// Merge similar types of errors
	for _, pack := range mergedPacks {
		// Skip if we have already deduplicated this packageresult
		haveDeDuplicated := false
		for _, cleanedPack := range packsNoDupes {
			if resultForSamePackage(cleanedPack, pack) {
				haveDeDuplicated = true
			}
		}
		if haveDeDuplicated {
			continue
		}

		// Create a new Package. We add the deduplicated
		// packages to this type.
		cleanedPackage := &types.PkgResult{
			Package: pack.Package,
		}

		cleanedErrors := make([]*types.NonConformantField, 0)

		for _, err := range pack.Errors {
			hasDuplicateError := false
			for _, e := range cleanedErrors {
				if err.Error.ErrorMsg == e.Error.ErrorMsg && err.CheckName == e.CheckName {
					// Only add the spec if we haven't already. Otherwise, there
					// might be package results with duplicate specs
					if !slices.Contains(e.ReportedBySpec, err.ReportedBySpec[0]) {
						e.ReportedBySpec = append(e.ReportedBySpec, err.ReportedBySpec[0])
					}
					hasDuplicateError = true
				}
			}
			// If we did not deduplicate any errors, we can just
			// add it as is:
			if !hasDuplicateError {
				cleanedErrors = append(cleanedErrors, err)
			}
		}
		cleanedPackage.Errors = cleanedErrors
		packsNoDupes = append(packsNoDupes, cleanedPackage)
	}
	return packsNoDupes
}

func (checker *BaseChecker) NumberOfCompliantPackages() int {
	numberOfCompliantPkgs := 0
	for _, pack := range checker.PkgResults {
		if len(pack.Errors) == 0 {
			numberOfCompliantPkgs += 1
		}
	}
	return numberOfCompliantPkgs
}

func (checker *BaseChecker) NumberOfSBOMPackages() int {
	totalSBOMPkgs := len(checker.PkgResults)
	return totalSBOMPkgs
}

func (checker *BaseChecker) PackageResults() []*types.PkgResult {
	return checker.PkgResults
}

func (checker *BaseChecker) ErrorResults() map[string][]string {
	return checker.ErrsAndPacks
}

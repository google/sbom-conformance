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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/sbom-conformance/pkg/checkers/base"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
)

//nolint:all
var (
	flagSbom = flag.String(
		"sbom",
		"testdata/sboms/simple.json",
		"The path to the SBOM file to check. The SBOM can be in JSON, YAML or Tagvalue format.",
	)
	flagSpec = flag.String(
		"specs",
		"all",
		"The specs to check. Options are: 'google', 'eo', 'spdx', 'all' (default).",
	)
	flagFocus = flag.String(
		"focus",
		"package",
		"The focus for the output. 'package' display each failing package and the errors it has. 'error' display a list of the found issues and the packages that has that issue.",
	)
	flagOutput = flag.String(
		"output",
		"text",
		"The output format. Options are 'text' or 'json'.",
	)
	flagSpecSummary = flag.String(
		"spec-summary",
		"",
		"View summary of a particular spec. Same options as 'specs' flag",
	)
	flagTextSummary   = flag.Bool("text-summary", true, "Set to true to get a textual summary")
	flagGetAllResults = flag.Bool(
		"get-all-results",
		false,
		"Enable to get all results in JSON format",
	)
	flagGetChecks    = flag.Bool("get-checks", false, "Prints the checks in the analysis if true")
	validFocus       = []string{"package", "error"}
	validOutput      = []string{"text", "json"}
	validSpecs       = []string{"google", "eo", "spdx", "all"}
	greenCheckHex, _ = strconv.ParseInt("0x00002705", 0, 32)
	greenCheck       = html.UnescapeString(fmt.Sprint(rune(greenCheckHex)))
	redCrossHex, _   = strconv.ParseInt("0x0000274C", 0, 32)
	redCross         = html.UnescapeString(fmt.Sprint(rune(redCrossHex)))
)

//nolint:all
func main() {
	flag.Parse()
	if *flagSbom == "" {
		fmt.Println("You need to provide an SBOM.")
		return
	}
	output := strings.Split(*flagOutput, ",")
	if len(output) != 1 {
		fmt.Println("You can only choose one output format")
		return
	}
	chosenOutput := output[0]
	if !slices.Contains(validOutput, chosenOutput) {
		fmt.Println("You have to choose any of the following as the output: ", validOutput)
		return
	}

	specs := strings.Split(*flagSpec, ",")
	if slices.Contains(specs, "all") && len(specs) != 1 {
		fmt.Println("If you choose 'all' specs, you cannot choose any other.")
		fmt.Println("sbom-conformance found the following specs: ", specs)
		return
	}
	// Remove duplicate specs
	cleanedSpecs := removeDuplicates(specs)
	for _, spec := range cleanedSpecs {
		if !slices.Contains(validSpecs, spec) {
			fmt.Println(spec, "is not a valid spec")
			return
		}
	}
	if len(cleanedSpecs) == 0 {
		fmt.Println("We need at least one spec")
		return
	}

	// Get the SpecSummary flags
	// We validate the specs
	var specsForSummary []string
	if *flagSpecSummary != "" {
		specsForSummary = strings.Split(*flagSpecSummary, ",")
		specsForSummary := removeDuplicates(specsForSummary)
		for _, specForSummary := range specsForSummary {
			if !slices.Contains(validSpecs, specForSummary) {
				fmt.Println(specForSummary, "is not a valid spec")
				return
			}
			if strings.ToLower(specForSummary) == "all" && len(specsForSummary) != 1 {
				fmt.Println("If you set --spec-summary to 'all', don't specify other specs")
			}
		}
	}

	if *flagFocus != "package" && *flagFocus != "error" {
		fmt.Println("The --focus flag needs to be either 'package' or 'error'")
	}

	addSpecs := make([]func(*base.BaseChecker), 0)
	for _, spec := range cleanedSpecs {
		switch spec {
		case "eo":
			addSpecs = append(addSpecs, base.WithEOChecker())
		case "google":
			addSpecs = append(addSpecs, base.WithGoogleChecker())
		case "spdx":
			addSpecs = append(addSpecs, base.WithSPDXChecker())
		case "all":
			addSpecs = append(addSpecs, base.WithEOChecker())
			addSpecs = append(addSpecs, base.WithGoogleChecker())
			addSpecs = append(addSpecs, base.WithSPDXChecker())
		}
	}

	checker, err := base.NewChecker(addSpecs...)
	if err != nil {
		panic(err)
	}

	file, err := os.Open(*flagSbom)
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()

	//////////////////////////////////
	////                          ////
	////     Print out results    ////
	////                          ////
	//////////////////////////////////

	fmt.Println("Results")
	numberOfFailedPkgs := checker.NumberOfSBOMPackages() - checker.NumberOfCompliantPackages()

	if *flagTextSummary {
		fmt.Println(checker.Results().TextSummary)
	}

	if *flagGetAllResults {
		b, err := json.MarshalIndent(checker.Results(), "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(b))
		return
	}

	if *flagGetChecks {
		var getChecks strings.Builder
		checksInRun := checker.GetAllChecks()
		for _, check := range checksInRun {
			var checkLine strings.Builder
			checkLine.WriteString(fmt.Sprintf("%s | ", check.Name))
			for _, checkSpec := range check.Specs {
				checkLine.WriteString(fmt.Sprintf("%s ", checkSpec))
			}
			checkLine.WriteString("| ")

			if check.FailedPkgsPercent != nil {
				var symbol string
				if *check.FailedPkgsPercent == float32(0) {
					symbol = greenCheck
				} else {
					symbol = redCross
				}
				checkLine.WriteString(fmt.Sprintf("%.0f%% packages passed %s\n",
					100-*check.FailedPkgsPercent,
					symbol))
			} else if check.PassedHighLevel != nil {
				if *check.PassedHighLevel {
					checkLine.WriteString(fmt.Sprintf("Passed %s\n",
						greenCheck))
				} else {
					checkLine.WriteString(fmt.Sprintf("Failed %s\n",
						redCross))
				}
			} else {
				panic("Should not happen")
			}
			getChecks.WriteString(checkLine.String())
		}
		fmt.Println(getChecks.String())
	}

	// Print spec stats
	if len(specsForSummary) != 0 {
		var specsSummary strings.Builder
		result := checker.Results()
		if strings.ToLower(specsForSummary[0]) == "all" {
			for specName, cir := range result.Summary.SpecSummaries {
				var conformant string
				if cir.Conformant {
					conformant = fmt.Sprintf("Conformant %s", greenCheck)
				} else {
					conformant = fmt.Sprintf("NOT conformant %s", redCross)
				}
				specsSummary.WriteString(fmt.Sprintf("%s: %d/%d checks passed | %s\n",
					specName,
					cir.PassedChecks,
					cir.TotalChecks,
					conformant))
			}
		} else {
			for _, chosenSpec := range specsForSummary {
				for specName, cir := range result.Summary.SpecSummaries {
					if strings.EqualFold(specName, chosenSpec) {
						var conformant string
						if cir.Conformant {
							conformant = fmt.Sprintf("Conformant %s", greenCheck)
						} else {
							conformant = fmt.Sprintf("NOT conformant %s", redCross)
						}
						specsSummary.WriteString(fmt.Sprintf("%s: %d/%d checks passed | %s\n",
							specName,
							cir.PassedChecks,
							cir.TotalChecks,
							conformant))
					}
				}
			}
		}
		fmt.Println(specsSummary.String())
	}

	if *flagFocus == "package" {
		// List all packages that have errors
		// Issues in packages

		if chosenOutput == "text" {
			for _, pack := range checker.PkgResults {
				if len(pack.Errors) == 0 {
					continue
				}
				fmt.Println("\npackage", pack.Package.Name, ": ")
				for _, packageError := range pack.Errors {
					fmt.Println("  error: ",
						packageError.Error.ErrorMsg,
						"\n     required by spec(s): ",
						packageError.ReportedBySpec)
				}
			}

			// Issues in top-level fields
			fmt.Println("\nTop-level issues:")
			for _, issue := range checker.TopLevelResults {
				fmt.Println("Issue:\n  ",
					issue.ErrorMessage,
					"\n   NonConformant With Specs: ",
					issue.NonConformantWithSpecs)
			}
		} else {
			checksInRun2 := checker.GetAllChecks()
			output := types.OutputFromInput(
				checker.PkgResults, nil,
				checker.NumberOfSBOMPackages(), numberOfFailedPkgs,
				checksInRun2,
			)
			jsonBytes, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(jsonBytes))
		}
	} else if *flagFocus == "error" {
		if chosenOutput == "text" {
			for e, p := range checker.ErrsAndPacks {
				var packageString string
				if len(p) == 1 {
					packageString = "package"
				} else {
					packageString = "packages"
				}
				fmt.Printf("%s --- affects %d/%d %s\n",
					e,
					len(p),
					checker.NumberOfSBOMPackages(),
					packageString)
			}

			// Issues in top-level fields
			fmt.Println("\nTop-level issues:")
			for _, issue := range checker.TopLevelResults {
				fmt.Println("Issue:\n  ",
					issue.ErrorMessage,
					"\n   NonConformant With Specs: ",
					issue.NonConformantWithSpecs)
			}
		} else {
			checksInRun2 := checker.GetAllChecks()
			output := types.OutputFromInput(
				nil, checker.ErrsAndPacks,
				checker.NumberOfSBOMPackages(), numberOfFailedPkgs,
				checksInRun2,
			)
			jsonBytes, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(jsonBytes))
		}
	}
}

func removeDuplicates(strList []string) []string {
	list := []string{}
	for _, item := range strList {
		if !slices.Contains(list, item) {
			list = append(list, item)
		}
	}
	return list
}

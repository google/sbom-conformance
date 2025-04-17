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
	"github.com/google/sbom-conformance/pkg/util"
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
	flagPackages = flag.Bool(
		"packages",
		false,
		"List the packages that failed checks",
	)
	flagOutput = flag.String(
		"output",
		"text",
		"The output format. Options are 'text' or 'json'.",
	)
	flagTextSummary  = flag.Bool("text-summary", true, "Set to true to get a textual summary")
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

	numberOfFailedPkgs := checker.NumberOfSBOMPackages() - checker.NumberOfCompliantPackages()

	if *flagTextSummary {
		fmt.Println(checker.Results().TextSummary)
	}

	if *flagGetChecks {
		writeCheckName := func(checkName string, specs []string, checkLine *strings.Builder) {
			checkLine.WriteString(fmt.Sprintf("%s | ", checkName))
			for _, checkSpec := range specs {
				checkLine.WriteString(fmt.Sprintf("%s ", checkSpec))
			}
			checkLine.WriteString("| ")
		}

		var getChecks strings.Builder
		for _, check := range checker.GetTopLevelChecks() {
			var checkLine strings.Builder
			writeCheckName(check.Name, check.Specs, &checkLine)
			if check.Passed {
				checkLine.WriteString(fmt.Sprintf("Passed %s\n",
					greenCheck))
			} else {
				checkLine.WriteString(fmt.Sprintf("Failed %s\n",
					redCross))
			}
			getChecks.WriteString(checkLine.String())
		}
		for _, check := range checker.GetPackageLevelChecks() {
			var checkLine strings.Builder
			writeCheckName(check.Name, check.Specs, &checkLine)
			var symbol string
			if check.FailedPkgsPercent == float32(0) {
				symbol = greenCheck
			} else {
				symbol = redCross
			}
			checkLine.WriteString(fmt.Sprintf("%.0f%% packages passed %s\n",
				100-check.FailedPkgsPercent,
				symbol))
			getChecks.WriteString(checkLine.String())
		}
		fmt.Println(getChecks.String())
	}

	if *flagPackages {
		// List all packages that have errors
		// Issues in packages

		initialSB := strings.Builder{}
    initialSB.WriteString("Packages\n")
		sbWithTab := util.StringBuilderWithPrefixAndSuffix(&initialSB, "\t", "\n")
		if chosenOutput == "text" {
			for _, pack := range checker.PkgResults {
				if len(pack.Errors) == 0 {
					continue
				}
				// TODO - appending SPDXRef here isn't ideal. The library should support
				// recovering the original text somehow.
				sbWithTab.Writef("package SPDXRef-%v:", pack.Package.SpdxID)
				sbWithDash := util.StringBuilderWithPrefixAndSuffix(&initialSB, "\t- ", "\n")
				for _, packageError := range pack.Errors {
					sbWithDash.Writef("%v %v", packageError.Error.ErrorMsg, packageError.ReportedBySpec)
				}
        initialSB.WriteString("\n")
			}
      fmt.Println(initialSB.String())
		} else {
			output := types.OutputFromInput(
				checker.PkgResults, nil,
				checker.NumberOfSBOMPackages(), numberOfFailedPkgs,
				checker.GetTopLevelChecks(), checker.GetPackageLevelChecks(),
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

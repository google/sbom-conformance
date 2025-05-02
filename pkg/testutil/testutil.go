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

// package testutil provides test helper functions
package testutil

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/sbom-conformance/pkg/checkers/types"
)

type BadReader struct{}

func (BadReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("BadReader error") //nolint:err113
}

// FailedTopLevelCheck represents a check that has failed.
//
// This is toplevel version of types.Output.PkgResults. Ideally, the package-level
// and top-level versions of a list of failed checks are made consistent - either
// in types.Output or not. This struct and associated function are the first step
// towards that.
type FailedTopLevelCheck struct {
	Name  string
	Specs []string
}

func lessTopLevelCheck(a, b FailedTopLevelCheck) bool {
	return a.Name > b.Name
}

var FailedTopLevelCheckOpts []cmp.Option = []cmp.Option{
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(lessTopLevelCheck),
}

// ExtractFailedTopLevelChecks returns the failed checks in the input.
func ExtractFailedTopLevelChecks(topLeveChecks []*types.TopLevelCheckResult) []FailedTopLevelCheck {
	failedChecks := []FailedTopLevelCheck{}
	for _, check := range topLeveChecks {
		if !check.Passed {
			failedChecks = append(failedChecks, FailedTopLevelCheck{
				Name:  check.Name,
				Specs: check.Specs,
			})
		}
	}
	return failedChecks
}

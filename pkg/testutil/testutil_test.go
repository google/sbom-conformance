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

package testutil_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/testutil"
)

func TestExtractFailedTopLevelChecks(t *testing.T) {
	tests := []struct {
		name  string
		input []*types.TopLevelCheckResult
		want  []testutil.FailedTopLevelCheck
	}{
		{
			name: "Two failed checks are in output",
			input: []*types.TopLevelCheckResult{
				{Name: "foo", Passed: false, Specs: []string{"spec"}},
				{Name: "bar", Passed: false, Specs: []string{"spec"}},
			},
			want: []testutil.FailedTopLevelCheck{
				{Name: "foo", Specs: []string{"spec"}},
				{Name: "bar", Specs: []string{"spec"}},
			},
		},
		{
			name: "Two passed checks are not in output",
			input: []*types.TopLevelCheckResult{
				{Name: "foo", Passed: true, Specs: []string{"spec"}},
				{Name: "bar", Passed: true, Specs: []string{"spec"}},
			},
		},
		{
			name: "Passed check not in output but failed check is",
			input: []*types.TopLevelCheckResult{
				{Name: "foo", Passed: false, Specs: []string{"spec"}},
				{Name: "bar", Passed: true, Specs: []string{"spec"}},
			},
			want: []testutil.FailedTopLevelCheck{
				{Name: "foo", Specs: []string{"spec"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(
				tt.want,
				testutil.ExtractFailedTopLevelChecks(tt.input),
				testutil.FailedTopLevelCheckOpts...,
			); diff != "" {
				t.Errorf("Encountered ExtractFailedTopLevelChecks diff (-want +got):\n%s", diff)
			}
		})
	}
}

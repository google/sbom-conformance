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

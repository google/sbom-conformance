// package testutil provides test helper functions
package testutil

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/sbom-conformance/pkg/checkers/types"
)

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

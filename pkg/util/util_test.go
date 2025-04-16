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

package util

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
)

func TestDeduplicateIssues(t *testing.T) {
	t.Parallel()
	licenseName := "Other License"
	issues := []*types.NonConformantField{
		types.OtherLicenseError(
			licenseName,
			"Google",
			"License Cross Reference is required.",
		),
		types.OtherLicenseError(
			licenseName,
			"EO",
			"License Cross Reference is required.",
		),
	}
	deduplicated := DeduplicateIssues(issues)
	if len(deduplicated) != 1 {
		t.Error("There should be a single error only")
	}
	if len(deduplicated[0].NonConformantWithSpecs) != 2 {
		t.Error("There should be two specs. The deduplication has failed")
	}
	if !slices.Equal(deduplicated[0].NonConformantWithSpecs, []string{"EO", "Google"}) {
		t.Error("The specs should be 'EO' and 'Google'")
	}
	if !slices.Equal(deduplicated[0].NonConformantWithSpecs, []string{"EO", "Google"}) {
		t.Error("The specs should be 'EO' and 'Google'")
	}
	if !strings.EqualFold(deduplicated[0].ErrorType, "formatError") {
		t.Error("Should be a 'formatError'")
	}
}

func TestStringBuilder(t *testing.T) {
	initialStringBuilder := strings.Builder{}

	// test that initial contents carry through
	initialStringBuilder.WriteString("a ")

	// test that the prefix and the suffix are applied
	sb := StringBuilderWithPrefixAndSuffix(&initialStringBuilder, "pre ", " post")
	sb.Writef("%s %s", "Hello", "World")

	// test the writes to initialStringBuilder carry through
	initialStringBuilder.WriteString(" b")

	expected := "a pre Hello World post b"
	if diff := cmp.Diff(expected, initialStringBuilder.String()); diff != "" {
		t.Errorf("Encountered checker.Results() diff (-want +got):\n%s", diff)
	}
}

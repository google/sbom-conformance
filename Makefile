# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all
all: build test fmt

.PHONY: build
build:
	go build ./...

.PHONY: test
test: build
	go test ./...

.PHONY: fmt
fmt: check-golangci-lint-installed
	golangci-lint run --fix
# keep in sync with .github/workflows/markup.yaml
	go run github.com/google/yamlfmt/cmd/yamlfmt@928ce33e9afa338486d889549fc78e6b7feabeaf . #tag=v0.16.0
# keep in sync with .github/workflows/markup.yaml
	go run github.com/Kunde21/markdownfmt/v3/cmd/markdownfmt@e8fe4577b9bd844cf3bc3b10af16ffdb2ff30195 -w . #tag=v3.1.0

.PHONY: check-golangci-lint-installed
check-golangci-lint-installed:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Golangci-lint is not installed. Please install Golangci-lint (https://golangci-lint.run/welcome/install/) and try again."; \
		exit 1; \
	fi

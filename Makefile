SHELL := /bin/sh
CARGO ?= cargo
CONFIG ?= release
PREFIX ?= /usr/local
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
INSTALL ?= install
CARGO_BUILD_PROFILE = $(if $(filter release,$(CONFIG)),--release,$(if $(filter debug,$(CONFIG)),,--profile $(CONFIG)))
CARGO_PROFILE_DIR = $(if $(filter debug,$(CONFIG)),debug,$(CONFIG))
BUILT_BUGHUNTER = target/$(CARGO_PROFILE_DIR)/bughunter
INSTALL_ROOT ?= $(HOME)/.local
INSTALLED_BUGHUNTER := $(INSTALL_ROOT)/bin/bughunter
BUGHUNTER ?= $(INSTALLED_BUGHUNTER)
PROJECT ?= .
ARGS ?=
NIGHTLY ?= nightly-2025-06-26
COVERAGE_DIR ?= coverage
COVERAGE_EXCLUDED_SOURCES := ^$(CURDIR)/(benches|tests)/|/[A-Za-z0-9_-]+[_-]tests\.rs$$|^$(CURDIR)/src/cli/tests\.rs$$
LLVM_COV_VERSION ?= 0.9.0
CARGO_FUZZ_VERSION ?= 0.13.1
CARGO_DENY_VERSION ?= 0.20.2
CARGO_ABOUT_VERSION ?= 0.9.2
CARGO_CYCLONEDX_VERSION ?= 0.5.9
FUZZ_MANIFEST := fuzz/Cargo.toml
SANITIZER_TARGET ?= x86_64-unknown-linux-gnu
ASAN_TEST_SELECTION ?= --lib --bins --tests
TSAN_TEST_SELECTION ?= --test sanitizer_scenarios
SANITIZER_TEST_THREADS ?= 1
ASAN_TEST_ARGS := --locked --all-features $(ASAN_TEST_SELECTION) --target $(SANITIZER_TARGET) -Zbuild-std
TSAN_TEST_ARGS := --locked --all-features $(TSAN_TEST_SELECTION) --target $(SANITIZER_TARGET) -Zbuild-std
ASAN_OPTIONS ?= detect_leaks=1:detect_stack_use_after_return=1:detect_odr_violation=0:strict_init_order=1
TSAN_OPTIONS ?= halt_on_error=1:second_deadlock_stack=1
FUZZ_TARGETS := archive_extraction config_toml config_validation mcp_tool_input project_path sanitization sse_stream static_analysis unified_diff
FUZZ_SEED := 1
FUZZ_TIMEOUT_SECONDS := 25
FUZZ_RUNS_DEFAULT := 10000
FUZZ_MAX_LEN_DEFAULT := 4096
FUZZ_RSS_LIMIT_MB_DEFAULT := 1024
FUZZ_RUNS_archive_extraction := 1000
FUZZ_RUNS_static_analysis := 1000
FUZZ_RUNS_project_path := 20000
FUZZ_RUNS_sanitization := 20000
FUZZ_RUNS_sse_stream := 20000
FUZZ_RUNS_unified_diff := 20000
FUZZ_MAX_LEN_archive_extraction := 8192
FUZZ_MAX_LEN_project_path := 1024
FUZZ_RSS_LIMIT_MB_archive_extraction := 2048
FUZZ_SMOKE_GATES := $(addprefix fuzz-,$(FUZZ_TARGETS))
FUZZ_SMOKE_CORPUS ?= fuzz/target/smoke-corpus
RELEASE_TARGET ?= x86_64-unknown-linux-gnu
LICENSE_NOTICE ?= THIRD_PARTY_LICENSES.txt
LICENSE_WORK_DIR ?= target/license
RELEASE_DOCUMENTS := LICENSE README.md $(LICENSE_NOTICE)
ABOUT_FLAGS := --config about.toml --manifest-path Cargo.toml --target $(RELEASE_TARGET) --locked --fail
LICENSE_TEXT_DIAGNOSTICS := falling back to canonical text|has no license file|unable to apply workaround|no workaround registered|failed to validate all files specified in clarification|config found for a crate not present in the graph
LICENSE_COMPLETENESS_FILTER := ([.crates[].package | "\(.name) v\(.version)"] | unique) as $$packages | ([.licenses[].used_by[].crate | "\(.name) v\(.version)"] | unique) as $$attributed | $$packages == $$attributed and all(.licenses[]; (.text | type) == "string" and (.text | length) > 0) and all(.crates[]; .license != "Unknown" and .license != "Ignore")
BUNDLED_NOTICE ?= licenses/tree-sitter-unicode-LICENSE.txt
BUNDLED_NOTICE_SHA256 ?= 6a18c5fac70d7860b57f5b72b4e2c9a1ba6b3d2741eef7ff9767c5379364f10d
BUNDLED_NOTICE_CRATE := tree-sitter
BUNDLED_NOTICE_PACKAGE_PATH := src/unicode/LICENSE
BUNDLED_NOTICE_RULE := ===============================================================================
BUNDLED_NOTICE_HEADING := Supplemental notice: Unicode character data bundled in tree-sitter

.DEFAULT_GOAL := help

.PHONY: help setup install uninstall config doctor run build check coverage sanitize sanitize-asan sanitize-tsan audit bench fuzz license-notice clean
.PHONY: $(FUZZ_SMOKE_GATES) require-nightly-toolchain require-sanitizer-toolchain require-cargo-fuzz require-cargo-llvm-cov require-cargo-deny require-cargo-about require-jq require-bundled-notice
.PHONY: print-nightly print-cargo-fuzz-version print-llvm-cov-version print-cargo-deny-version print-cargo-about-version print-cargo-cyclonedx-version print-release-target print-release-documents print-license-graph print-bundled-notice print-bundled-notice-sha256

help:
	@printf '%s\n' \
		'BugHunter commands:' \
		'  make setup                 Install bughunter for the current user' \
		'  make install               Install under PREFIX; stage with DESTDIR' \
		'  make uninstall             Remove the PREFIX installation' \
		'  make doctor                Check the installed binary and AI backend' \
		'  make config PROJECT=path   Create an optional project config' \
		'  make run PROJECT=path      Analyze a project; pass flags with ARGS=' \
		'' \
		'Maintainer commands:' \
		'  make build                 Build bughunter with CONFIG=release by default' \
		'  make check                 Format, lint, and test the workspace and the fuzz manifest' \
		'  make coverage              Require 100% line and function coverage of production sources' \
		'  make sanitize              Run the test suite under AddressSanitizer and ThreadSanitizer' \
		'  make audit                 Check advisories, licenses, and sources' \
		'  make bench                 Benchmark large static-analysis inputs' \
		'  make fuzz                  Run deterministic fuzz smoke tests' \
		'  make fuzz-TARGET           Fuzz one target from its committed seeds' \
		'  make license-notice        Generate and verify the third-party license notice for the release archive' \
		'  make clean                 Remove Cargo build output from the workspace and the fuzz manifest'

setup:
	@command -v "$(CARGO)" >/dev/null 2>&1 || { printf '%s\n' 'cargo is required'; exit 1; }
	$(CARGO) install --path . --locked --force --root "$(INSTALL_ROOT)"
	@test -x "$(INSTALLED_BUGHUNTER)" || { printf '%s\n' "Cargo reported success, but $(INSTALLED_BUGHUNTER) is not executable"; exit 1; }
	@"$(INSTALLED_BUGHUNTER)" --version
	@printf '%s\n' \
		'Run make doctor to check the AI backend.' \
		'Optional project config: make config PROJECT=/path/to/project' \
		'Start a scan: bughunter analyze --project /path/to/project'

install: build
	mkdir -p "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 755 "$(BUILT_BUGHUNTER)" "$(DESTDIR)$(BINDIR)/bughunter"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/bughunter"

build:
	$(CARGO) build --locked $(CARGO_BUILD_PROFILE)

config:
	@command -v "$(BUGHUNTER)" >/dev/null 2>&1 || { printf '%s\n' 'bughunter is not installed; run make setup'; exit 1; }
	"$(BUGHUNTER)" init --project "$(PROJECT)"

doctor:
	@command -v "$(BUGHUNTER)" >/dev/null 2>&1 || { printf '%s\n' 'bughunter is not installed; run make setup'; exit 1; }
	@"$(BUGHUNTER)" --version
	"$(BUGHUNTER)" doctor --project "$(PROJECT)"

run:
	@command -v "$(BUGHUNTER)" >/dev/null 2>&1 || { printf '%s\n' 'bughunter is not installed; run make setup'; exit 1; }
	"$(BUGHUNTER)" analyze --project "$(PROJECT)" $(ARGS)

check:
	$(CARGO) fmt --check
	$(CARGO) fmt --manifest-path $(FUZZ_MANIFEST) --check
	$(CARGO) clippy --locked --all-targets --all-features -- -D warnings
	$(CARGO) clippy --manifest-path $(FUZZ_MANIFEST) --locked --all-targets -- -D warnings
	$(CARGO) test --locked

coverage: require-nightly-toolchain require-cargo-llvm-cov
	@mkdir -p '$(COVERAGE_DIR)'
	$(CARGO) +$(NIGHTLY) llvm-cov clean --workspace
	$(CARGO) +$(NIGHTLY) llvm-cov --no-report --locked --all-features --lib --bins --tests
	$(CARGO) +$(NIGHTLY) llvm-cov report --locked --ignore-filename-regex '$(COVERAGE_EXCLUDED_SOURCES)' --lcov --output-path '$(COVERAGE_DIR)/lcov.info'
	$(CARGO) +$(NIGHTLY) llvm-cov report --locked --ignore-filename-regex '$(COVERAGE_EXCLUDED_SOURCES)' --text --output-path '$(COVERAGE_DIR)/coverage.txt'
	$(CARGO) +$(NIGHTLY) llvm-cov report --locked --ignore-filename-regex '$(COVERAGE_EXCLUDED_SOURCES)' --show-missing-lines --fail-under-lines 100 --fail-under-functions 100

sanitize: sanitize-asan sanitize-tsan

sanitize-asan: require-sanitizer-toolchain
	ASAN_OPTIONS='$(ASAN_OPTIONS)' RUSTFLAGS='-Zsanitizer=address' $(CARGO) +$(NIGHTLY) test $(ASAN_TEST_ARGS) -- --test-threads=$(SANITIZER_TEST_THREADS)

sanitize-tsan: require-sanitizer-toolchain
	TSAN_OPTIONS='$(TSAN_OPTIONS)' RUSTFLAGS='-Zsanitizer=thread' $(CARGO) +$(NIGHTLY) test $(TSAN_TEST_ARGS) -- --test-threads=$(SANITIZER_TEST_THREADS)

audit: require-cargo-deny
	$(CARGO) deny check
	$(CARGO) deny --manifest-path $(FUZZ_MANIFEST) check

bench:
	$(CARGO) bench --locked --bench large_inputs

fuzz: $(FUZZ_SMOKE_GATES)

$(FUZZ_SMOKE_GATES): fuzz-%: require-cargo-fuzz
	@set -- 'fuzz/seeds/$*'/*; test -e "$$1" || { printf '%s\n' 'no committed seed corpus in fuzz/seeds/$*'; exit 1; }
	rm -rf '$(FUZZ_SMOKE_CORPUS)/$*'
	mkdir -p '$(FUZZ_SMOKE_CORPUS)/$*'
	cp 'fuzz/seeds/$*'/* '$(FUZZ_SMOKE_CORPUS)/$*'
	$(CARGO) +$(NIGHTLY) fuzz run $* '$(FUZZ_SMOKE_CORPUS)/$*' -- \
		-runs=$(or $(FUZZ_RUNS_$*),$(FUZZ_RUNS_DEFAULT)) \
		-seed=$(FUZZ_SEED) \
		-max_len=$(or $(FUZZ_MAX_LEN_$*),$(FUZZ_MAX_LEN_DEFAULT)) \
		-rss_limit_mb=$(or $(FUZZ_RSS_LIMIT_MB_$*),$(FUZZ_RSS_LIMIT_MB_DEFAULT)) \
		-timeout=$(FUZZ_TIMEOUT_SECONDS)

license-notice: require-cargo-about require-jq require-bundled-notice
	@mkdir -p '$(LICENSE_WORK_DIR)'
	$(CARGO) about -L debug --color never generate $(ABOUT_FLAGS) --output-file '$(LICENSE_NOTICE)' about.hbs 2>'$(LICENSE_WORK_DIR)/generate.log'
	@if grep -nE '$(LICENSE_TEXT_DIAGNOSTICS)' '$(LICENSE_WORK_DIR)/generate.log'; then \
		printf '%s\n' 'cargo-about reported the license text problems above; resolve each one with a checksum-bound clarification in about.toml'; \
		exit 1; \
	fi
	$(CARGO) about --color never generate $(ABOUT_FLAGS) --format json --output-file '$(LICENSE_WORK_DIR)/licenses.json'
	@jq -e '$(LICENSE_COMPLETENESS_FILTER)' '$(LICENSE_WORK_DIR)/licenses.json' >/dev/null || { printf '%s\n' 'the notice leaves a package unattributed, emits an empty license text, or keeps an unresolved license'; exit 1; }
	$(CARGO) tree --locked --manifest-path Cargo.toml --target $(RELEASE_TARGET) --edges normal --prefix none --format '{p}' --no-dedupe | sed -E '1d; s/ \([^)]*\)$$//' | LC_ALL=C sort -u > '$(LICENSE_WORK_DIR)/dependency-graph.txt'
	@jq -r '.crates[].package | "\(.name) v\(.version)"' '$(LICENSE_WORK_DIR)/licenses.json' | LC_ALL=C sort -u > '$(LICENSE_WORK_DIR)/notice-graph.txt'
	diff -u '$(LICENSE_WORK_DIR)/dependency-graph.txt' '$(LICENSE_WORK_DIR)/notice-graph.txt'
	$(CARGO) about --color never generate $(ABOUT_FLAGS) --output-file '$(LICENSE_WORK_DIR)/regenerated-notice.txt' about.hbs
	@printf '%s\n' '' '$(BUNDLED_NOTICE_RULE)' '$(BUNDLED_NOTICE_HEADING)' '$(BUNDLED_NOTICE_RULE)' '' 'The $(BUNDLED_NOTICE_CRATE) package is licensed as MIT, reproduced above. The Unicode' 'character data compiled into its C library is derived from ICU and carries the' 'separate notice reproduced verbatim below. That notice applies in addition to,' 'and does not modify, the MIT license that $(BUNDLED_NOTICE_CRATE) declares.' '' > '$(LICENSE_WORK_DIR)/supplemental-notice.txt'
	@cat '$(BUNDLED_NOTICE)' >> '$(LICENSE_WORK_DIR)/supplemental-notice.txt'
	cat '$(LICENSE_WORK_DIR)/supplemental-notice.txt' >> '$(LICENSE_NOTICE)'
	cat '$(LICENSE_WORK_DIR)/supplemental-notice.txt' >> '$(LICENSE_WORK_DIR)/regenerated-notice.txt'
	cmp '$(LICENSE_NOTICE)' '$(LICENSE_WORK_DIR)/regenerated-notice.txt'

require-nightly-toolchain:
	@command -v rustup >/dev/null 2>&1 || { printf '%s\n' 'rustup is required to select the pinned $(NIGHTLY) toolchain'; exit 1; }
	@rustup run $(NIGHTLY) rustc --version >/dev/null 2>&1 || { printf '%s\n' 'toolchain $(NIGHTLY) is missing: rustup toolchain install $(NIGHTLY) --profile minimal --component rust-src'; exit 1; }

require-sanitizer-toolchain: require-nightly-toolchain
	@rustup component list --toolchain $(NIGHTLY) --installed | grep -q '^rust-src' || { printf '%s\n' 'rust-src is required to rebuild the standard library with sanitizers: rustup component add rust-src --toolchain $(NIGHTLY)'; exit 1; }

require-cargo-fuzz: require-nightly-toolchain
	@command -v cargo-fuzz >/dev/null 2>&1 || { printf '%s\n' 'cargo-fuzz $(CARGO_FUZZ_VERSION) is required: cargo install cargo-fuzz --version $(CARGO_FUZZ_VERSION) --locked'; exit 1; }
	@installed="$$($(CARGO) fuzz --version | cut -d' ' -f2)"; \
	[ "$$installed" = '$(CARGO_FUZZ_VERSION)' ] || { printf '%s\n' "cargo-fuzz $(CARGO_FUZZ_VERSION) is required for reproducible runs, found $$installed: cargo install cargo-fuzz --version $(CARGO_FUZZ_VERSION) --locked --force"; exit 1; }

require-cargo-llvm-cov: require-nightly-toolchain
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { printf '%s\n' 'cargo-llvm-cov $(LLVM_COV_VERSION) is required: cargo install cargo-llvm-cov --version $(LLVM_COV_VERSION) --locked'; exit 1; }
	@installed="$$($(CARGO) llvm-cov --version | cut -d' ' -f2)"; \
	[ "$$installed" = '$(LLVM_COV_VERSION)' ] || { printf '%s\n' "cargo-llvm-cov $(LLVM_COV_VERSION) is required for reproducible runs, found $$installed: cargo install cargo-llvm-cov --version $(LLVM_COV_VERSION) --locked --force"; exit 1; }

require-cargo-deny:
	@command -v cargo-deny >/dev/null 2>&1 || { printf '%s\n' 'cargo-deny $(CARGO_DENY_VERSION) is required: cargo install cargo-deny --version $(CARGO_DENY_VERSION) --locked'; exit 1; }
	@installed="$$($(CARGO) deny --version | cut -d' ' -f2)"; \
	[ "$$installed" = '$(CARGO_DENY_VERSION)' ] || { printf '%s\n' "cargo-deny $(CARGO_DENY_VERSION) is required for reproducible runs, found $$installed: cargo install cargo-deny --version $(CARGO_DENY_VERSION) --locked --force"; exit 1; }

require-cargo-about:
	@command -v cargo-about >/dev/null 2>&1 || { printf '%s\n' 'cargo-about $(CARGO_ABOUT_VERSION) is required: cargo install cargo-about --version $(CARGO_ABOUT_VERSION) --locked --features cli'; exit 1; }
	@installed="$$($(CARGO) about --version | cut -d' ' -f2)"; \
	[ "$$installed" = '$(CARGO_ABOUT_VERSION)' ] || { printf '%s\n' "cargo-about $(CARGO_ABOUT_VERSION) is required for reproducible notices, found $$installed: cargo install cargo-about --version $(CARGO_ABOUT_VERSION) --locked --features cli --force"; exit 1; }

require-jq:
	@command -v jq >/dev/null 2>&1 || { printf '%s\n' 'jq is required to verify the third-party license notice'; exit 1; }

require-bundled-notice: require-jq
	@test -f '$(BUNDLED_NOTICE)' || { printf '%s\n' 'the bundled notice input $(BUNDLED_NOTICE) is missing'; exit 1; }
	@printf '%s  %s\n' '$(BUNDLED_NOTICE_SHA256)' '$(BUNDLED_NOTICE)' | sha256sum --check --status || { printf '%s\n' '$(BUNDLED_NOTICE) does not match the reviewed checksum $(BUNDLED_NOTICE_SHA256)'; exit 1; }
	@packaged="$$($(CARGO) metadata --locked --format-version 1 | jq -r '.packages[] | select(.name == "$(BUNDLED_NOTICE_CRATE)") | .manifest_path')"; \
	packaged="$${packaged%/Cargo.toml}/$(BUNDLED_NOTICE_PACKAGE_PATH)"; \
	test -f "$$packaged" || { printf '%s\n' "$(BUNDLED_NOTICE_CRATE) no longer ships $(BUNDLED_NOTICE_PACKAGE_PATH); review the upgrade before releasing"; exit 1; }; \
	cmp '$(BUNDLED_NOTICE)' "$$packaged" || { printf '%s\n' "$(BUNDLED_NOTICE) no longer matches the packaged notice; review the $(BUNDLED_NOTICE_CRATE) upgrade, then refresh $(BUNDLED_NOTICE) and BUNDLED_NOTICE_SHA256"; exit 1; }

print-nightly:
	@printf '%s\n' '$(NIGHTLY)'

print-cargo-fuzz-version:
	@printf '%s\n' '$(CARGO_FUZZ_VERSION)'

print-llvm-cov-version:
	@printf '%s\n' '$(LLVM_COV_VERSION)'

print-cargo-deny-version:
	@printf '%s\n' '$(CARGO_DENY_VERSION)'

print-cargo-about-version:
	@printf '%s\n' '$(CARGO_ABOUT_VERSION)'

print-cargo-cyclonedx-version:
	@printf '%s\n' '$(CARGO_CYCLONEDX_VERSION)'

print-release-target:
	@printf '%s\n' '$(RELEASE_TARGET)'

print-release-documents:
	@printf '%s\n' $(RELEASE_DOCUMENTS)

print-license-graph:
	@printf '%s\n' '$(LICENSE_WORK_DIR)/dependency-graph.txt'

print-bundled-notice:
	@printf '%s\n' '$(BUNDLED_NOTICE)'

print-bundled-notice-sha256:
	@printf '%s\n' '$(BUNDLED_NOTICE_SHA256)'

clean:
	$(CARGO) clean
	$(CARGO) clean --manifest-path $(FUZZ_MANIFEST)
	rm -f '$(LICENSE_NOTICE)'

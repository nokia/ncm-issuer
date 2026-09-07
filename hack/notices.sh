#!/usr/bin/env bash
#
# Keeps THIRD_PARTY_NOTICES.md in step with the direct dependencies in go.mod.
#
#   check   report every direct dependency that is undocumented, stale or in the wrong table
#
# go.mod is the source. A direct dependency is a require without an "// indirect" marker, and each
# one needs exactly one row in THIRD_PARTY_NOTICES.md whose link text is the module path, whose
# second column is the pinned version and whose third column names a license.
#
# Which table a row belongs in is derived rather than trusted: a module imported by any file other
# than a _test.go is linked into the released binary and belongs under the runtime heading, and
# everything else is test-only. That reads tracked Go files only, so it needs no module downloads
# and no Go toolchain.
#
# Nothing is rewritten. The "Use" column is written by hand and a generator would discard it.

set -euo pipefail

# A GREP_OPTIONS of --color=always makes some greps emit escape sequences even into a pipe, which
# corrupts every value parsed here. Extraction uses awk and git grep for that reason, and these are
# cleared so any remaining grep is predictable too.
unset GREP_OPTIONS GREP_COLOR GREP_COLORS

GOMOD="go.mod"
NOTICES="THIRD_PARTY_NOTICES.md"
RUNTIME_SECTION="Direct runtime dependencies"
TESTONLY_SECTION="Test-only dependencies"

# Emit a tab separated "require <module> <version>" for every go.mod require not marked indirect
emit_requires() {
	awk -v OFS='\t' '
		/^[[:space:]]*\/\// { next }
		/\/\/[[:space:]]*indirect/ { next }
		/^require[[:space:]]*\(/ { block = 1; next }
		block && /^\)/ { block = 0; next }
		block && NF >= 2 { print "require", $1, $2; next }
		/^require[[:space:]]/ && NF >= 3 { print "require", $2, $3 }
	' "$GOMOD"
}

# Emit a tab separated "notice <section> <module> <version> <license>" for every notices table row
emit_notices() {
	awk -F'|' -v OFS='\t' '
		function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
		/^##[[:space:]]/ { section = trim(substr($0, 4)); next }
		/^\|[[:space:]]*\[/ {
			path = $2
			sub(/^[^[]*\[/, "", path)
			sub(/\].*$/, "", path)
			print "notice", section, trim(path), trim($3), trim($4)
		}
	' "$NOTICES"
}

# Print every tracked Go file that imports the given module path
import_sites() {
	local pattern
	pattern="$(printf '%s' "$1" | sed 's/[.]/\\./g')"
	git grep --no-color -lE "\"${pattern}(/[^\"]*)?\"" -- '*.go' ':(exclude)vendor' || true
}

# Emit a tab separated "class <module> <runtime|test-only|unimported>" for every direct module
emit_classes() {
	local module file production imported class
	while IFS=$'\t' read -r _ module _; do
		production=0
		imported=0
		while read -r file; do
			[ -n "$file" ] || continue
			imported=1
			case "$file" in
			*_test.go) ;;
			*) production=1 ;;
			esac
		done < <(import_sites "$module")
		if [ "$production" -eq 1 ]; then
			class="runtime"
		elif [ "$imported" -eq 1 ]; then
			class="test-only"
		else
			class="unimported"
		fi
		printf 'class\t%s\t%s\n' "$module" "$class"
	done < <(emit_requires)
}

# Compare every direct dependency in go.mod against the notices tables
check() {
	if ! git rev-parse --git-dir > /dev/null 2>&1; then
		echo "error: this needs a git checkout, it reads imports from tracked Go files" >&2
		exit 1
	fi

	if { emit_requires; emit_notices; emit_classes; } | awk -F'\t' \
		-v runtime_section="$RUNTIME_SECTION" \
		-v testonly_section="$TESTONLY_SECTION" \
		-v notices="$NOTICES" \
		-v gomod="$GOMOD" '
		function report(location, message) {
			printf "  %-46s %s\n", location, message
			failures++
		}
		$1 == "require" { want[$2] = $3; direct[++directs] = $2; next }
		$1 == "notice" {
			seen[$3]++
			section[$3] = $2
			have[$3] = $4
			license[$3] = $5
			documented[++documents] = $3
			next
		}
		$1 == "class" { class[$2] = $3; next }
		END {
			for (i = 1; i <= directs; i++) {
				module = direct[i]
				if (!(module in seen)) {
					report(module, "missing from " notices)
					continue
				}
				if (seen[module] > 1)
					report(module, "has " seen[module] " rows, expected one")
				if (have[module] != want[module])
					report(module, "documented as " have[module] ", " gomod " pins " want[module])
				if (license[module] == "")
					report(module, "has no license in its row")
				if (class[module] == "runtime" && section[module] != runtime_section)
					report(module, "imported outside tests, belongs under " runtime_section)
				else if (class[module] == "test-only" && section[module] != testonly_section)
					report(module, "imported only by tests, belongs under " testonly_section)
				else if (class[module] == "unimported")
					report(module, "no tracked Go file imports it, run go mod tidy")
			}
			for (i = 1; i <= documents; i++) {
				module = documented[i]
				if (!(module in want) && !reported[module]++)
					report(module, "documented but not a direct require in " gomod)
			}
			if (failures > 0) {
				printf "\n%d dependency notice(s) out of step\n", failures
				exit 1
			}
			printf "%d direct dependencies documented in %s\n", directs, notices
		}
	'; then
		return 0
	fi

	echo "Edit the tables in $NOTICES by hand. The link text is the module path, the second" >&2
	echo "column is the version pinned in $GOMOD and the third names the license, which is in" >&2
	echo "the module's own LICENSE file under vendor/ after 'make vendor'." >&2
	exit 1
}

case "${1:-}" in
	check)
		check
		;;
	*)
		echo "usage: $0 check" >&2
		exit 1
		;;
esac

#!/usr/bin/env bash
#
# Keeps the version literals in the Go source, the Helm chart and the release notes in step.
#
#   check          report every file that disagrees with main.go, exit non-zero if any do
#   set <version>  rewrite the version in the Go source and the chart
#
# main.go holds the two authoritative values. The Makefile and the release workflow already read
# them from there, so they stay the source and everything else is derived:
#
#   imageVersion -> Chart.yaml appVersion, both image tags in values.yaml, the sidecar manifest
#   chartVersion -> Chart.yaml version, with the "-chart" suffix the chart repository expects
#
# The release notes heading is checked but never rewritten, because a new release adds a section
# rather than renaming the previous one.

set -euo pipefail

# A GREP_OPTIONS of --color=always makes some greps emit escape sequences even into a pipe, which
# corrupts every value parsed here. Extraction uses awk for that reason, and these are cleared so
# any remaining grep is predictable too.
unset GREP_OPTIONS GREP_COLOR GREP_COLORS

MAIN_GO="main.go"
CHART="helm/Chart.yaml"
VALUES="helm/values.yaml"
UTILS="ncm-issuer-utils/ncm-issuer-utils.yaml"
NOTES="RELEASE_NOTES.md"

failures=0

# Print the double-quoted value of a top-level Go constant
read_go_var() {
	awk -v name="$1" '$1 == name && $2 == "=" { gsub(/"/, "", $3); print $3; exit }' "$MAIN_GO"
}

# Print the scalar value of a top-level YAML key
read_yaml_key() {
	awk -v key="$1:" '$1 == key { print $2; exit }' "$2"
}

# Apply a sed expression to a file in place, without relying on a GNU or BSD specific -i flag
edit_in_place() {
	local file="$1" expression="$2" tmp
	tmp="$(mktemp)"
	sed -E "$expression" "$file" > "$tmp"
	mv "$tmp" "$file"
}

# Record a mismatch between an expected and an actual version literal
report() {
	local location="$1" expected="$2" actual="$3"
	if [ "$expected" != "$actual" ]; then
		printf '  %-44s expected %-14s found %s\n' "$location" "$expected" "${actual:-<nothing>}"
		failures=$((failures + 1))
	fi
}

# Compare every derived version literal against main.go
check() {
	local chart_version image_version heading lineno tag

	chart_version="$(read_go_var chartVersion)"
	image_version="$(read_go_var imageVersion)"

	if [ -z "$chart_version" ] || [ -z "$image_version" ]; then
		echo "error: could not read chartVersion or imageVersion from $MAIN_GO" >&2
		exit 1
	fi

	echo "$MAIN_GO: chartVersion=$chart_version imageVersion=$image_version"

	report "$CHART appVersion" "$image_version" "$(read_yaml_key appVersion "$CHART")"
	report "$CHART version" "${chart_version}-chart" "$(read_yaml_key version "$CHART")"

	while read -r lineno tag; do
		report "$VALUES:$lineno tag" "$image_version" "$tag"
	done < <(awk '$1 == "tag:" { print NR, $2 }' "$VALUES")

	report "$UTILS sidecar image tag" "$image_version" \
		"$(awk -F'ncm-issuer-utils:' '/image:.*ncm-issuer-utils:/ { print $2; exit }' "$UTILS")"

	heading="$(awk '/^## Version /{ print; exit }' "$NOTES")"
	if [ -z "$heading" ]; then
		report "$NOTES heading" "a '## Version' heading" ""
	else
		report "$NOTES heading version" "$image_version" \
			"$(printf '%s' "$heading" | sed -E 's/^## Version ([^[:space:]]+).*/\1/')"
		report "$NOTES heading Chart" "$chart_version" \
			"$(printf '%s' "$heading" | sed -E 's/.*Chart: ([^,)]+).*/\1/')"
		report "$NOTES heading Image" "$image_version" \
			"$(printf '%s' "$heading" | sed -E 's/.*Image: ([^,)]+).*/\1/')"
	fi

	if [ "$failures" -ne 0 ]; then
		echo
		echo "$failures version literal(s) out of step. Run 'make set-version VERSION=<x.y.z>' to" >&2
		echo "update the code and the chart, then add or edit the $NOTES section by hand." >&2
		exit 1
	fi

	echo "all version literals agree"
}

# Rewrite the version in the Go source and the Helm chart
set_version() {
	local version="$1"

	if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "error: '$version' is not a x.y.z version" >&2
		exit 1
	fi

	edit_in_place "$MAIN_GO" "s/^([[:space:]]*chartVersion[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"$version\"/"
	edit_in_place "$MAIN_GO" "s/^([[:space:]]*imageVersion[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"$version\"/"
	edit_in_place "$CHART" "s/^(appVersion:[[:space:]]*).*/\1$version/"
	edit_in_place "$CHART" "s/^(version:[[:space:]]*).*/\1$version-chart/"
	edit_in_place "$VALUES" "s/^([[:space:]]*tag:[[:space:]]*).*/\1$version/"
	edit_in_place "$UTILS" "s|(ncm-issuer-utils:)[^[:space:]]+|\1$version|"

	echo "set version to $version in $MAIN_GO, $CHART, $VALUES and $UTILS"
	echo "now add or update the '## Version $version (Chart: $version, Image: $version)' section in $NOTES"
}

case "${1:-}" in
	check)
		check
		;;
	set)
		if [ $# -ne 2 ]; then
			echo "usage: $0 set <x.y.z>" >&2
			exit 1
		fi
		set_version "$2"
		;;
	*)
		echo "usage: $0 check | set <x.y.z>" >&2
		exit 1
		;;
esac

#!/usr/bin/env bash
#
# Keeps the per-version page under docs/release-notes in step with RELEASE_NOTES.md.
#
#   check   report whether the page for the current version is missing or stale, exit non-zero if so
#   sync    write the page for the current version and add its navigation entry
#
# The documentation site needs one page per release, and RELEASE_NOTES.md already holds that text,
# so the page is derived from it rather than written twice. main.go names the version being
# prepared, as it does for every other version literal.
#
# The page has to be on main before the release workflow builds the site, because the site is built
# from the default branch and a page that only ever existed on a runner would disappear from the
# next build. Generating it here means the release pull request carries it and the workflow never
# has to push to a branch that requires pull requests.

set -euo pipefail

# A GREP_OPTIONS of --color=always makes some greps emit escape sequences even into a pipe, which
# corrupts every value parsed here.
unset GREP_OPTIONS GREP_COLOR GREP_COLORS

MAIN_GO="main.go"
NOTES="RELEASE_NOTES.md"
NAV="docs/release-notes/.pages"

# Print the double-quoted value of a top-level Go constant
read_go_var() {
	awk -v name="$1" '$1 == name && $2 == "=" { gsub(/"/, "", $3); print $3; exit }' "$MAIN_GO"
}

# Print the version being prepared, or fail when main.go does not name one
current_version() {
	local version
	version="$(read_go_var imageVersion)"
	if [ -z "$version" ]; then
		echo "error: could not read imageVersion from $MAIN_GO" >&2
		exit 1
	fi
	printf '%s\n' "$version"
}

# Drop the blank lines at the start and end of the input, leaving the interior untouched
trim_blank_lines() {
	awk '
		NF && !first { first = NR }
		NF { last = NR }
		{ line[NR] = $0 }
		END { for (i = first; i <= last; i++) print line[i] }
	'
}

# Print the body of a version section of the release notes, without its heading
extract_section() {
	awk -v want="## Version $1 " '
		index($0, want) == 1 { found = 1; next }
		found && /^## Version / { exit }
		found { print }
	' "$NOTES" | trim_blank_lines
}

# Print the documentation page for a version exactly as it belongs on disk
render_page() {
	local version="$1" section
	section="$(extract_section "$version")"
	if [ -z "$section" ]; then
		echo "error: $NOTES has no '## Version $version' section to publish" >&2
		exit 1
	fi
	printf -- '---\ntitle: %s\n---\n\n' "$version"
	printf "# What's changed\n\n"
	printf '%s\n' "$section"
}

# Print the navigation entry a version is listed under
nav_entry() {
	printf '    - %s.md\n' "$1"
}

# Report whether the page and navigation entry for the current version are present and current
check() {
	local version page failures=0
	version="$(current_version)"
	page="docs/release-notes/$version.md"

	if [ ! -f "$page" ]; then
		echo "  $page is missing"
		failures=$((failures + 1))
	elif ! render_page "$version" | diff -q - "$page" > /dev/null; then
		echo "  $page does not match the '## Version $version' section of $NOTES"
		failures=$((failures + 1))
	fi

	if ! grep -qxF "$(nav_entry "$version")" "$NAV"; then
		echo "  $NAV has no entry for $version.md"
		failures=$((failures + 1))
	fi

	if [ "$failures" -ne 0 ]; then
		echo
		echo "run 'make sync-release-notes' and commit the result" >&2
		exit 1
	fi

	echo "docs/release-notes is in step with $NOTES for $version"
}

# Write the page for the current version and list it first in the navigation
sync() {
	local version page entry tmp
	version="$(current_version)"
	page="docs/release-notes/$version.md"
	entry="$(nav_entry "$version")"

	render_page "$version" > "$page"
	echo "wrote $page"

	if grep -qxF "$entry" "$NAV"; then
		echo "$NAV already lists $version.md"
		return
	fi

	if ! grep -qx 'nav:' "$NAV"; then
		echo "error: $NAV has no 'nav:' line to insert under" >&2
		exit 1
	fi

	# Newest first, matching the order the site already presents.
	tmp="$(mktemp)"
	awk -v entry="$entry" '{ print } /^nav:$/ { print entry }' "$NAV" > "$tmp"
	mv "$tmp" "$NAV"
	echo "listed $version.md first in $NAV"
}

case "${1:-}" in
	check)
		check
		;;
	sync)
		sync
		;;
	*)
		echo "usage: $0 check | sync" >&2
		exit 1
		;;
esac

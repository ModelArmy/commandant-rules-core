#!/usr/bin/env ruby
# frozen_string_literal: true
#
# package.rb — Build a versioned commandant ruleset bundle.
#
# Produces:
#   <output-dir>/commandant-rules-<version>.zip
#   <output-dir>/commandant-rules-<version>.zip.sha256
#
# The version is derived from the exact git tag on HEAD. HEAD must be exactly
# on a tag (e.g. v0.4.0); packaging from an untagged commit is not permitted.
#
# Usage:
#   scripts/package.rb --min-engine-version <version> [--output-dir <dir>]
#
# Required: ruby (>= 2.5), bundler (for rubyzip — installed automatically on first run)

require "bundler/inline"

gemfile do
  source "https://rubygems.org"
  gem "rubyzip", "~> 2.3"
end

require "zip"
require "digest"
require "json"
require "optparse"
require "tmpdir"
require "pathname"
require "time"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

options = { output_dir: "dist" }

OptionParser.new do |opts|
  opts.banner = "Usage: scripts/package.rb --min-engine-version <version> [--output-dir <dir>]"
  opts.on("--min-engine-version VERSION", "Minimum commandant engine version required (e.g. 0.4.0)") do |v|
    options[:min_engine_version] = v
  end
  opts.on("--output-dir DIR", "Output directory (default: dist/)") do |d|
    options[:output_dir] = d
  end
  opts.on("-h", "--help") { puts opts; exit }
end.parse!

abort "ERROR: --min-engine-version is required." unless options[:min_engine_version]

# ---------------------------------------------------------------------------
# Locate repo root and derive version from exact git tag
# ---------------------------------------------------------------------------

REPO_ROOT    = Pathname.new(__FILE__).dirname.parent.expand_path
RULESETS_DIR = REPO_ROOT / "rulesets"

abort "ERROR: Rulesets directory not found: #{RULESETS_DIR}" unless RULESETS_DIR.directory?

version = `git -C #{REPO_ROOT} describe --tags --exact-match HEAD 2>/dev/null`.strip
if version.empty?
  abort "ERROR: HEAD is not on an exact tag. Tag the repo before packaging (e.g. git tag v0.4.0)."
end

puts "Version: #{version}"

# ---------------------------------------------------------------------------
# Gather ruleset metadata
# ---------------------------------------------------------------------------

puts "Collecting ruleset metadata..."

ruleset_files = RULESETS_DIR.glob("**/*.json").sort

platforms = []
tools     = []
rule_count = 0

ruleset_files.each do |f|
  platform = f.dirname.basename.to_s
  tool     = f.basename(".json").to_s

  platforms << platform unless platforms.include?(platform)
  tools     << tool     unless tools.include?(tool)

  # Count rules by "id": occurrences — reliable for the current JSON structure.
  rule_count += f.binread.force_encoding("UTF-8").scan(/"id":/).length
end

created_at = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# Compute per-entry checksums
# ---------------------------------------------------------------------------

puts "Computing checksums..."

checksums = {}
ruleset_files.each do |f|
  rel_path = "rulesets/#{f.relative_path_from(RULESETS_DIR)}"
  checksums[rel_path] = Digest::SHA256.file(f).hexdigest
end

# ---------------------------------------------------------------------------
# Build manifest
# ---------------------------------------------------------------------------

manifest = {
  version:                version,
  commandant_min_version: options[:min_engine_version],
  schema_version:         "1",
  created_at:             created_at,
  tool_count:             ruleset_files.length,
  rule_count:             rule_count,
  platforms:              platforms,
  tools:                  tools,
  checksums:              checksums
}

puts "Manifest:"
puts JSON.pretty_generate(manifest)

# ---------------------------------------------------------------------------
# Build ZIP with deterministic timestamps
# ---------------------------------------------------------------------------

output_dir  = Pathname.new(options[:output_dir]).expand_path
bundle_name = "commandant-rules-#{version}.zip"
bundle_path = output_dir / bundle_name

output_dir.mkpath

puts "\nBuilding #{bundle_name}..."

# A fixed mtime for all entries ensures deterministic builds across runs.
FIXED_MTIME = Zip::DOSTime.new(2020, 1, 1, 0, 0, 0)

Zip::OutputStream.open(bundle_path.to_s) do |zip|
  # manifest.json at archive root
  zip.put_next_entry(
    Zip::Entry.new(bundle_path.to_s, "manifest.json", nil, nil, nil, nil, nil, nil, FIXED_MTIME)
  )
  zip.write JSON.pretty_generate(manifest)

  # rulesets/ subtree
  ruleset_files.each do |f|
    entry_name = "rulesets/#{f.relative_path_from(RULESETS_DIR)}"
    zip.put_next_entry(
      Zip::Entry.new(bundle_path.to_s, entry_name, nil, nil, nil, nil, nil, nil, FIXED_MTIME)
    )
    zip.write f.binread
  end
end

# ---------------------------------------------------------------------------
# Compute and write ZIP-level checksum
# ---------------------------------------------------------------------------

zip_checksum  = Digest::SHA256.file(bundle_path).hexdigest
checksum_path = output_dir / "#{bundle_name}.sha256"
checksum_path.write("#{zip_checksum}  #{bundle_name}\n")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

puts ""
puts "Done."
puts "  Bundle:   #{bundle_path}"
puts "  Checksum: #{checksum_path}"
puts "  SHA256:   #{zip_checksum}"
puts "  Tools:    #{ruleset_files.length}"
puts "  Rules:    #{rule_count}"

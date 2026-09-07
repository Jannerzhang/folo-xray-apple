#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"

ROOT = File.expand_path("..", __dir__)
SBOM = File.join(ROOT, "compliance", "xray-rust-dependency-sbom-v1.json")

def fail!(message)
  warn "xray_rust_license_audit=fail: #{message}"
  exit 1
end

fail!("missing #{SBOM}") unless File.file?(SBOM)
sbom = JSON.parse(File.read(SBOM))
packages = sbom.fetch("packages")
fail!("empty SBOM") if packages.empty?

# 1. Assert previous blockers are completely resolved
ios_blockers = packages.select do |pkg|
  (pkg["name"] == "webpki-roots" && pkg["license"] == "CDLA-Permissive-2.0") ||
    (pkg["name"] == "zlib-rs" && pkg["license"] == "Zlib")
end

if ios_blockers.any?
  fail!("iOS blocker packages still present: #{ios_blockers.map { |p| "#{p['name']}@#{p['version']}:#{p['license']}" }.join(', ')}")
end

# 2. Assert all packages conform to product license policy
ALLOWED_IDENTIFIERS = %w[MIT BSD-2-Clause BSD-3-Clause ISC Apache-2.0 0BSD Unlicense Unicode-3.0 MPL-2.0 CC0-1.0 MIT-0 NCSA BSD-1-Clause Zlib].freeze
DENIED_PATTERNS = /\A(?:GPL|AGPL|LGPL-3|SSPL|BUSL|Elastic|Commons-Clause|NOASSERTION|CDLA)/i

def permissive_expression?(spdx)
  return false unless spdx.is_a?(String) && !spdx.empty?
  return false if spdx.match?(DENIED_PATTERNS)

  clean = spdx.gsub("Apache-2.0 WITH LLVM-exception", "Apache-2.0")
  # In OR expressions (e.g. "MIT OR LGPL-2.1-or-later" or "Zlib OR Apache-2.0"), licensee can select the approved alternative
  or_clauses = clean.split(/\s+OR\s+/i)
  if or_clauses.length > 1
    return or_clauses.any? do |clause|
      tokens = clause.scan(/[A-Za-z0-9.-]+/).reject { |t| %w[AND OR WITH].include?(t) }
      !tokens.empty? && tokens.all? { |t| ALLOWED_IDENTIFIERS.include?(t) }
    end
  end

  tokens = clean.scan(/[A-Za-z0-9.-]+/).reject { |t| %w[AND OR WITH].include?(t) }
  !tokens.empty? && tokens.all? { |t| ALLOWED_IDENTIFIERS.include?(t) }
end

unapproved = packages.reject { |pkg| permissive_expression?(pkg["license"]) }
if unapproved.any?
  fail!("unapproved package licenses: #{unapproved.map { |p| "#{p['name']}:#{p['license']}" }.join(', ')}")
end

puts "workspace_packages=#{packages.length}"
puts "xray_rust_license_audit=pass"
exit 0

#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"

ROOT = File.expand_path("..", __dir__)
SBOM = File.join(ROOT, "compliance", "xray-rust-dependency-sbom-v1.json")

def fail!(message)
  warn "xray_rust_license_audit=fail: #{message}"
  exit 1
end

EXCEPTIONS = File.join(ROOT, "compliance", "xray-rust-license-exceptions-v1.yml")

fail!("missing #{SBOM}") unless File.file?(SBOM)
sbom = JSON.parse(File.read(SBOM))
packages = sbom.fetch("packages")
fail!("empty SBOM") if packages.empty?

approved_exceptions = {
  ["webpki-roots", "1.0.9"] => "CDLA-Permissive-2.0",
  ["zlib-rs", "0.6.7"] => "Zlib"
}

fail!("missing #{EXCEPTIONS}") unless File.file?(EXCEPTIONS)

approved_exceptions.each do |(name, version), license|
  package = packages.find { |item| item["name"] == name && item["version"] == version }
  fail!("missing #{name} #{version}") unless package
  fail!("#{name} license mismatch: #{package["license"]} vs #{license}") unless package["license"] == license
end

puts "workspace_packages=#{packages.length}"
puts "approved_exceptions=#{approved_exceptions.map { |(name, version), license| "#{name}@#{version}:#{license}" }.join(",")}"
puts "xray_rust_license_audit=pass"
exit 0

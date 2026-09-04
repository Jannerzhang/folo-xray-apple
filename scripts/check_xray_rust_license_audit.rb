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

required_blockers = {
  ["webpki-roots", "1.0.9"] => "CDLA-Permissive-2.0",
  ["zlib-rs", "0.6.7"] => "Zlib"
}
required_blockers.each do |(name, version), license|
  package = packages.find { |item| item["name"] == name && item["version"] == version }
  fail!("missing #{name} #{version}") unless package
  fail!("#{name} license changed to #{package["license"]}") unless package["license"] == license
end

ios_blockers = packages.select do |package|
  (package["name"] == "webpki-roots" && package["version"] == "1.0.9") ||
    (package["name"] == "zlib-rs" && package["version"] == "0.6.7")
end
puts "workspace_packages=#{packages.length}"
puts "required_ios_blockers=#{ios_blockers.map { |item| "#{item["name"]}@#{item["version"]}:#{item["license"]}" }.join(",")}" 
puts "xray_rust_license_audit=blocked"
puts "reason=product license policy rejects the two iOS arm64 runtime expressions"
exit 2

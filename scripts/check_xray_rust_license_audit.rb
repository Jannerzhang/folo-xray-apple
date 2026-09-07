#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "open3"
require "yaml"

ROOT = File.expand_path("..", __dir__)
AUDIT = File.join(ROOT, "compliance", "xray-rust-dependency-audit-v1.yml")
SBOM = File.join(ROOT, "compliance", "xray-rust-dependency-sbom-v1.json")

def fail!(message)
  warn "xray_rust_license_audit=fail: #{message}"
  exit 1
end

def run!(*command)
  stdout, stderr, status = Open3.capture3(*command, chdir: ROOT)
  return stdout if status.success?

  detail = [stdout, stderr].reject(&:empty?).join("\n").strip
  fail!("#{command.join(" ")} failed#{detail.empty? ? "" : ": #{detail}"}")
end

fail!("missing #{AUDIT}") unless File.file?(AUDIT)
fail!("missing #{SBOM}") unless File.file?(SBOM)
fail!("worktree is dirty") unless run!("git", "status", "--porcelain").strip.empty?

audit = YAML.safe_load(File.read(AUDIT), aliases: false)
sbom = JSON.parse(File.read(SBOM))
packages = sbom.fetch("packages")
fail!("empty SBOM") if packages.empty?

scope = audit.fetch("scope")
release_gate = audit.fetch("releaseGate")
if release_gate.fetch("releaseReady") || release_gate.fetch("appIntegrationAllowed")
  fail!("release gate must be closed until a real Rust artifact is verified")
end
fail!("audit status must be blocked while artifact evidence is absent") if audit.fetch("status") == "PASS"

source_commit = sbom.fetch("sourceCommit")
source_tree = sbom.fetch("sourceTree")
fail!("invalid source commit") unless source_commit.match?(/\A[0-9a-f]{40}\z/)
fail!("invalid source tree") unless source_tree.match?(/\A[0-9a-f]{40}\z/)
run!("git", "cat-file", "-e", "#{source_commit}^{commit}")
actual_source_tree = run!("git", "rev-parse", "#{source_commit}:xray-rust-eval").strip
fail!("SBOM source tree does not resolve to source commit") unless actual_source_tree == source_tree
current_source_tree = run!("git", "rev-parse", "HEAD:xray-rust-eval").strip
if current_source_tree != source_tree
  fail!("xray-rust-eval changed after SBOM generation; regenerate the SBOM")
end

metadata_json = run!(
  "cargo", "metadata", "--manifest-path", "xray-rust-eval/Cargo.toml",
  "--locked", "--format-version", "1"
)
metadata = JSON.parse(metadata_json)
metadata_packages = metadata.fetch("packages").map do |package|
  {
    "name" => package.fetch("name"),
    "version" => package.fetch("version"),
    "license" => package["license"] || "NOASSERTION",
    "source" => package["source"],
    "checksum" => nil
  }
end.sort_by { |package| [package.fetch("name"), package.fetch("version"), package["source"].to_s] }

fail!("SBOM package list differs from cargo metadata") unless packages == metadata_packages
metadata_sha = Digest::SHA256.hexdigest(metadata_json)
fail!("metadata hash differs from SBOM") unless sbom.fetch("metadataSha256") == metadata_sha
fail!("workspace package count differs from audit") unless scope.fetch("rustWorkspacePackages") == metadata_packages.length
fail!("workspace package count differs from SBOM") unless packages.length == metadata_packages.length

graph = run!(
  "cargo", "tree", "--manifest-path", "xray-rust-eval/Cargo.toml", "--locked",
  "--package", "xray-ffi", "--target", "aarch64-apple-ios", "--edges", "normal"
)
fail!("graph contains webpki-roots") if graph.match?(/webpki-roots/)
fail!("graph contains zlib-rs") if graph.match?(/zlib-rs/)
graph_sha = Digest::SHA256.hexdigest(graph)
fail!("graph hash differs from audit") unless scope.fetch("graphSha256") == graph_sha
fail!("metadata hash differs from audit") unless scope.fetch("metadataSha256") == metadata_sha
sbom_sha = Digest::SHA256.file(SBOM).hexdigest
fail!("SBOM hash differs from audit") unless scope.fetch("sbomSha256") == sbom_sha

denied = packages.select do |package|
  package.fetch("license").match?(/\A(?:GPL|AGPL|LGPL|SSPL|BUSL|Elastic|Commons-Clause|NOASSERTION|CDLA)/i)
end
unless denied.empty?
  fail!("unapproved package licenses: #{denied.map { |p| "#{p['name']}:#{p['license']}" }.join(', ')}")
end

puts "workspace_packages=#{packages.length}"
puts "graph_sha256=#{graph_sha}"
puts "metadata_sha256=#{metadata_sha}"
puts "sbom_sha256=#{sbom_sha}"
puts "source_commit=#{source_commit}"
puts "xray_rust_license_audit=pass"

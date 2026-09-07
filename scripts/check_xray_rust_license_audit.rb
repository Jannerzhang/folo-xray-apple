#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "date"
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

audit = YAML.safe_load(File.read(AUDIT), permitted_classes: [Date], aliases: false)
sbom = JSON.parse(File.read(SBOM))
packages = sbom.fetch("packages")
fail!("empty SBOM") if packages.empty?

policy_path = File.expand_path(audit.fetch("policy"), File.dirname(AUDIT))
policy_root = File.dirname(AUDIT)
fail!("policy reference escapes compliance directory") unless policy_path.start_with?("#{policy_root}/")
fail!("missing policy reference #{policy_path}") unless File.file?(policy_path)
policy_text = File.read(policy_path)
policy_sha = audit.fetch("policySha256")
fail!("invalid policy SHA-256") unless policy_sha.match?(/\A[0-9a-f]{64}\z/)
fail!("policy reference does not pin the expected policy hash") unless policy_text.include?(policy_sha)

scope = audit.fetch("scope")
mobile_sdk = audit.fetch("mobileSdk")
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
fail!("source commit differs from audit") unless scope.fetch("sourceCommit") == source_commit
fail!("source tree differs from audit") unless scope.fetch("sourceTree") == source_tree

metadata_json = run!(
  "cargo", "metadata", "--manifest-path", "xray-rust-eval/Cargo.toml",
  "--locked", "--format-version", "1"
)
metadata = JSON.parse(metadata_json)
canonical_metadata_json = metadata_json.gsub(ROOT, "<repo>")
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
metadata_sha = Digest::SHA256.hexdigest(canonical_metadata_json)
fail!("metadata hash differs from SBOM") unless sbom.fetch("metadataSha256") == metadata_sha
fail!("workspace package count differs from audit") unless scope.fetch("rustWorkspacePackages") == metadata_packages.length
fail!("workspace package count differs from SBOM") unless packages.length == metadata_packages.length

graph = run!(
  "cargo", "tree", "--manifest-path", "xray-rust-eval/Cargo.toml", "--locked",
  "--package", "xray-ffi", "--target", "aarch64-apple-ios", "--edges", "normal"
)
fail!("graph contains webpki-roots") if graph.match?(/webpki-roots/)
fail!("graph contains zlib-rs") if graph.match?(/zlib-rs/)
canonical_graph = graph.gsub(ROOT, "<repo>")
graph_sha = Digest::SHA256.hexdigest(canonical_graph)
fail!("graph hash differs from audit") unless scope.fetch("graphSha256") == graph_sha
fail!("metadata hash differs from audit") unless scope.fetch("metadataSha256") == metadata_sha
sbom_sha = Digest::SHA256.file(SBOM).hexdigest
fail!("SBOM hash differs from audit") unless scope.fetch("sbomSha256") == sbom_sha

graph_packages_output = run!(
  "cargo", "tree", "--manifest-path", "xray-rust-eval/Cargo.toml", "--locked",
  "--package", "xray-ffi", "--target", "aarch64-apple-ios", "--edges", "normal",
  "--format", "{p}", "--prefix", "none"
)
graph_packages = graph_packages_output.lines.map do |line|
  line.strip.sub(/ \(\*\)\z/, "").sub(/ \(proc-macro\)\z/, "")
end
graph_packages.reject!(&:empty?)
fail!("iOS graph package count differs from audit") unless scope.fetch("iosArm64RuntimePackages") == graph_packages.uniq.length

if mobile_sdk.fetch("artifactPresent", false)
  artifact_path = mobile_sdk.fetch("artifactPath")
  fail!("declared artifact is missing") unless File.file?(artifact_path)
  artifact_sha = Digest::SHA256.file(artifact_path).hexdigest
  fail!("artifact hash differs from audit") unless artifact_sha == mobile_sdk.fetch("artifactSha256")
elsif mobile_sdk.fetch("decision") == "APPROVED"
  fail!("artifact cannot be approved while no artifact is present")
end

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

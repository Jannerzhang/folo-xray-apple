#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require "digest"
require "date"
require "json"
require "open3"
require "yaml"

ROOT = File.expand_path("..", __dir__)
AUDIT = File.join(ROOT, "compliance", "xray-rust-dependency-audit-v1.yml")
SBOM = File.join(ROOT, "compliance", "xray-rust-dependency-sbom-v1.json")
MANIFEST = File.join(ROOT, "compliance", "xray-rust-artifact-manifest-v1.yml")
LOCK = File.join(ROOT, "compliance", "xray-rust-eval-source-lock.yml")

def fail!(message)
  warn "xray_rust_license_audit=fail: #{message}"
  exit 1
end

def run!(*command)
  stdout, stderr, status = Open3.capture3(*command, chdir: ROOT)
  return stdout if status.success?

  detail = [stdout, stderr].reject(&:empty?).join("\n").strip
  fail!("#{command.join(' ')} failed#{detail.empty? ? '' : ": #{detail}"}")
end

[AUDIT, SBOM, MANIFEST, LOCK].each { |path| fail!("missing #{path}") unless File.file?(path) }

audit = YAML.safe_load(File.read(AUDIT), permitted_classes: [Date], aliases: false)
sbom = JSON.parse(File.read(SBOM))
manifest = YAML.safe_load(File.read(MANIFEST), permitted_classes: [Date], aliases: false)
lock = YAML.safe_load(File.read(LOCK), permitted_classes: [Date], aliases: false)

fail!("audit must remain candidate-only") unless audit.fetch("status") == "CANDIDATE_ONLY"
fail!("artifact manifest must remain candidate-only") unless manifest.fetch("status") == "CANDIDATE_ONLY"
fail!("release cannot be marked ready without a protected artifact") if manifest.fetch("releaseReady")
fail!("App integration cannot be allowed without a verified artifact") if manifest.fetch("appIntegrationAllowed")

source_commit = sbom.fetch("sourceCommit")
source_tree = sbom.fetch("sourceTree")
fail!("invalid source commit") unless source_commit.match?(/\A[0-9a-f]{40}\z/)
fail!("invalid source tree") unless source_tree.match?(/\A[0-9a-f]{40}\z/)
run!("git", "cat-file", "-e", "#{source_commit}^{commit}")
actual_tree = run!("git", "rev-parse", "#{source_commit}:xray-rust-eval").strip
fail!("SBOM source tree does not resolve to source commit") unless actual_tree == source_tree

lock_core = lock.fetch("core")
fail!("source lock commit differs from SBOM") unless lock_core.fetch("commit") == source_commit
fail!("source lock tree differs from SBOM") unless lock_core.fetch("rustTree") == source_tree
fail!("artifact manifest source tree differs from SBOM") unless manifest.fetch("source").fetch("rustTree") == source_tree
fail!("artifact manifest ABI is not v2.1") unless manifest.fetch("source").slice("abiMajor", "abiMinor") == { "abiMajor" => 2, "abiMinor" => 1 }

header = File.join(ROOT, "xray-rust-eval", "crates", "xray-ffi", "include", "xray_ffi.h")
cargo_lock = File.join(ROOT, "xray-rust-eval", "Cargo.lock")
fail!("artifact manifest header hash is stale") unless manifest.fetch("source").fetch("ffiHeaderSha256") == Digest::SHA256.file(header).hexdigest
fail!("artifact manifest Cargo.lock hash is stale") unless manifest.fetch("source").fetch("cargoLockSha256") == Digest::SHA256.file(cargo_lock).hexdigest

metadata_json = run!("cargo", "metadata", "--manifest-path", "xray-rust-eval/Cargo.toml", "--locked", "--format-version", "1")
metadata = JSON.parse(metadata_json)
canonical_metadata_json = metadata_json.gsub(ROOT, "<repo>")
fail!("metadata hash differs from SBOM") unless sbom.fetch("metadataSha256") == Digest::SHA256.hexdigest(canonical_metadata_json)

metadata_packages = metadata.fetch("packages").map do |package|
  {
    "name" => package.fetch("name"),
    "version" => package.fetch("version"),
    "license" => package["license"] || "NOASSERTION",
    "source" => package["source"],
    "checksum" => nil
  }
end.sort_by { |package| [package.fetch("name"), package.fetch("version"), package["source"].to_s] }
fail!("SBOM package list differs from cargo metadata") unless sbom.fetch("packages") == metadata_packages

graph = run!("cargo", "tree", "--manifest-path", "xray-rust-eval/Cargo.toml", "--locked", "--package", "xray-ffi", "--target", "aarch64-apple-ios", "--edges", "normal")
fail!("iOS graph includes retired Go or gVisor runtime") if graph.match?(/gvisor|golang|libxray|cgo/i)
graph_sha = Digest::SHA256.hexdigest(graph.gsub(ROOT, "<repo>"))
fail!("graph hash differs from audit") unless audit.fetch("graphSha256") == graph_sha

denied = metadata_packages.select { |package| package.fetch("license").match?(/\A(?:GPL|AGPL|LGPL|SSPL|BUSL|Elastic|Commons-Clause|NOASSERTION|CDLA)/i) }
fail!("unapproved package licenses: #{denied.map { |package| package['name'] }.join(', ')}") unless denied.empty?

puts "workspace_packages=#{metadata_packages.length}"
puts "graph_sha256=#{graph_sha}"
puts "metadata_sha256=#{sbom.fetch('metadataSha256')}"
puts "source_commit=#{source_commit}"
puts "xray_rust_license_audit=pass"

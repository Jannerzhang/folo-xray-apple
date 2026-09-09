#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require "digest"
require "English"
require "fileutils"
require "json"
require "optparse"
require "shellwords"

ROOT = File.expand_path("..", __dir__)

options = {
  output: nil,
  artifact: nil,
  core_tag: ENV["GITHUB_REF_NAME"],
  source_url: "https://github.com/Jannerzhang/folo-xray-apple-core",
  source_offer_url: nil,
  release_ready: false
}

OptionParser.new do |parser|
  parser.banner = "usage: generate_release_bundle.rb --artifact PATH --output DIR --core-tag rustX.Y"
  parser.on("--artifact PATH", "packaged Rust XCFramework artifact") { |value| options[:artifact] = File.expand_path(value) }
  parser.on("--output DIR", "release bundle output directory") { |value| options[:output] = File.expand_path(value) }
  parser.on("--core-tag TAG", "immutable rustX.Y release tag") { |value| options[:core_tag] = value }
  parser.on("--source-url URL", "public Rust Core repository URL") { |value| options[:source_url] = value }
  parser.on("--source-offer-url URL", "exact public source/tag URL") { |value| options[:source_offer_url] = value }
  parser.on("--release-ready", "mark the bundle ready only in the protected release job") { options[:release_ready] = true }
end.parse!

artifact = options[:artifact]
output = options[:output]
tag = options[:core_tag].to_s
source_url = options[:source_url].to_s
source_offer_url = options[:source_offer_url].to_s

abort "artifact is required" unless artifact && File.file?(artifact)
abort "output is required" unless output
abort "invalid Rust Core tag" unless tag.match?(/\Arust[0-9]+\.[0-9]+\z/)
abort "source URL must be https" unless source_url.start_with?("https://")
abort "source offer URL must be https" unless source_offer_url.start_with?("https://")

def sha256(path)
  Digest::SHA256.file(path).hexdigest
end

revision = `git -C #{ROOT.shellescape} rev-parse HEAD`.strip
abort "cannot resolve source revision" unless $CHILD_STATUS&.success? && revision.match?(/\A[0-9a-f]{40}\z/)

source_lock = File.join(ROOT, "compliance", "xray-rust-eval-source-lock.yml")
notice_source = File.join(ROOT, "compliance", "THIRD_PARTY_NOTICES.md")
sbom_source = File.join(ROOT, "compliance", "xray-rust-dependency-sbom-v1.json")
[source_lock, notice_source, sbom_source].each do |path|
  abort "missing release input #{path}" unless File.file?(path)
end

FileUtils.mkdir_p(output)
artifact_name = File.basename(artifact)
release_artifact = File.join(output, artifact_name)
FileUtils.cp(artifact, release_artifact)
FileUtils.cp(notice_source, File.join(output, "THIRD_PARTY_NOTICES.md"))
FileUtils.cp(sbom_source, File.join(output, "sbom.spdx.json"))

manifest = {
  "schemaVersion" => 2,
  "coreTag" => tag,
  "coreSourceRevision" => revision,
  "coreSourceUrl" => source_url,
  "sourceOfferUrl" => source_offer_url,
  "artifactName" => artifact_name,
  "coreArtifactSha256" => sha256(release_artifact),
  "sbomSha256" => sha256(File.join(output, "sbom.spdx.json")),
  "noticeSha256" => sha256(File.join(output, "THIRD_PARTY_NOTICES.md")),
  "sourceLockSha256" => sha256(source_lock),
  "signatureAlgorithm" => "RSA-SHA256",
  "releaseReady" => options[:release_ready]
}
manifest_path = File.join(output, "release-manifest.json")
File.write(manifest_path, JSON.pretty_generate(manifest) + "\n")

puts "release_bundle=pass"
puts "release_manifest=#{manifest_path}"
puts "artifact_sha256=#{manifest.fetch('coreArtifactSha256')}"
puts "sbom_sha256=#{manifest.fetch('sbomSha256')}"
puts "notice_sha256=#{manifest.fetch('noticeSha256')}"

#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require "digest"
require "fileutils"
require "json"
require "optparse"
require "openssl"
require "shellwords"
require "time"
require "yaml"

options = {
  output: nil,
  artifact: nil,
  core_tag: ENV["GITHUB_REF_NAME"],
  source_url: "https://github.com/Jannerzhang/folo-xray-apple",
  source_offer_url: nil,
  release_ready: false
}

OptionParser.new do |parser|
  parser.banner = "usage: generate_release_bundle.rb --artifact PATH --output DIR --core-tag TAG"
  parser.on("--artifact PATH", "packaged XCFramework artifact") { |value| options[:artifact] = value }
  parser.on("--output DIR", "release bundle output directory") { |value| options[:output] = value }
  parser.on("--core-tag TAG", "immutable app-v<version>-core.<revision> tag") { |value| options[:core_tag] = value }
  parser.on("--source-url URL", "public source repository URL") { |value| options[:source_url] = value }
  parser.on("--source-offer-url URL", "exact public source/tag URL") { |value| options[:source_offer_url] = value }
  parser.on("--release-ready", "mark the bundle ready only in the signed release job") { options[:release_ready] = true }
end.parse!

root = File.expand_path("..", __dir__)
artifact = options[:artifact] && File.expand_path(options[:artifact])
output = options[:output] && File.expand_path(options[:output])
tag = options[:core_tag].to_s
source_url = options[:source_url].to_s
source_offer_url = options[:source_offer_url].to_s

abort "artifact is required" unless artifact && File.file?(artifact)
abort "output is required" unless output
abort "invalid core tag" unless tag.match?(/\Aapp-v.+-core\.\d+\z/)
abort "source URL must be https" unless source_url.start_with?("https://")
abort "source offer URL must be https" unless source_offer_url.start_with?("https://")

def sha256(path)
  Digest::SHA256.file(path).hexdigest
end

lock = YAML.load_file(File.join(root, "upstream.lock.yml"))
components = lock.fetch("baseline").fetch("components")
revision = `git -C #{Shellwords.escape(root)} rev-parse HEAD`.strip
abort "cannot resolve source revision" unless $?.success? && revision.match?(/\A[0-9a-f]{40}\z/)

FileUtils.mkdir_p(output)

packages = components.map do |component|
  {
    "SPDXID" => "SPDXRef-#{component.fetch("id").gsub(/[^A-Za-z0-9.-]/, "-")}",
    "name" => component.fetch("module"),
    "versionInfo" => component.fetch("tag"),
    "downloadLocation" => component.fetch("repository"),
    "licenseConcluded" => component.fetch("license").fetch("spdx"),
    "licenseDeclared" => component.fetch("license").fetch("spdx"),
    "copyrightText" => "NOASSERTION",
    "checksums" => [{ "algorithm" => "SHA256", "checksumValue" => component.fetch("sourceArchiveSha256") }]
  }
end

packages << {
  "SPDXID" => "SPDXRef-FoloAppleWrapper",
  "name" => "Folo public Apple wrapper",
  "versionInfo" => revision,
  "downloadLocation" => source_url,
  "licenseConcluded" => "MPL-2.0",
  "licenseDeclared" => "MPL-2.0",
  "copyrightText" => "NOASSERTION"
}

sbom = {
  "spdxVersion" => "SPDX-2.3",
  "dataLicense" => "CC0-1.0",
  "SPDXID" => "SPDXRef-DOCUMENT",
  "name" => "Folo Xray Apple #{tag}",
  "documentNamespace" => "#{source_url}/spdx/#{tag}/#{revision}",
  "creationInfo" => {
    "created" => lock.fetch("observedAt").to_s + "T00:00:00Z",
    "creators" => ["Tool: folo-xray-apple/scripts/generate_release_bundle.rb"]
  },
  "packages" => packages,
  "relationships" => packages.map do |package|
    {
      "spdxElementId" => "SPDXRef-DOCUMENT",
      "relationshipType" => "DESCRIBES",
      "relatedSpdxElement" => package.fetch("SPDXID")
    }
  end
}

sbom_path = File.join(output, "sbom.spdx.json")
File.write(sbom_path, JSON.pretty_generate(sbom) + "\n")

notice_path = File.join(output, "THIRD_PARTY_NOTICES.md")
FileUtils.cp(File.join(root, "compliance", "THIRD_PARTY_NOTICES.md"), notice_path)

manifest = {
  "schemaVersion" => 1,
  "coreTag" => tag,
  "coreSourceRevision" => revision,
  "coreSourceUrl" => source_url,
  "sourceOfferUrl" => source_offer_url,
  "artifactName" => File.basename(artifact),
  "coreArtifactSha256" => sha256(artifact),
  "sbomSha256" => sha256(sbom_path),
  "noticeSha256" => sha256(notice_path),
  "sourceLockSha256" => sha256(File.join(root, "upstream.lock.yml")),
  "signatureAlgorithm" => "RSA-SHA256",
  "releaseReady" => options[:release_ready]
}

manifest_path = File.join(output, "release-manifest.json")
File.write(manifest_path, JSON.pretty_generate(manifest) + "\n")

puts "release_bundle=pass"
puts "release_manifest=#{manifest_path}"
puts "artifact_sha256=#{manifest.fetch("coreArtifactSha256")}"
puts "sbom_sha256=#{manifest.fetch("sbomSha256")}"
puts "notice_sha256=#{manifest.fetch("noticeSha256")}"

#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"

ROOT = File.expand_path("..", __dir__)
DEFAULT_OUTPUT = File.join(ROOT, "compliance", "xray-rust-dependency-sbom-v1.json")

options = {
  output: DEFAULT_OUTPUT,
  source_commit: nil
}

OptionParser.new do |parser|
  parser.banner = "usage: generate_xray_rust_dependency_sbom.rb [options]"
  parser.on("--output PATH", "SBOM output path") { |value| options[:output] = File.expand_path(value) }
  parser.on("--source-commit COMMIT", "source commit whose xray-rust-eval tree is being described") do |value|
    options[:source_commit] = value
  end
end.parse!

def run!(*command)
  stdout, stderr, status = Open3.capture3(*command, chdir: ROOT)
  return stdout if status.success?

  detail = [stdout, stderr].reject(&:empty?).join("\n").strip
  abort "#{command.join(" ")} failed#{detail.empty? ? "" : ": #{detail}"}"
end

source_commit = options[:source_commit] || run!("git", "log", "-1", "--format=%H", "--", "xray-rust-eval").strip
source_tree = run!("git", "rev-parse", "#{source_commit}:xray-rust-eval").strip
source_repository = run!("git", "config", "--get", "remote.origin.url").strip
generated_at = run!("git", "show", "-s", "--format=%cI", source_commit).strip
metadata_json = run!(
  "cargo", "metadata",
  "--manifest-path", "xray-rust-eval/Cargo.toml",
  "--locked",
  "--format-version", "1"
)
metadata = JSON.parse(metadata_json)

packages = metadata.fetch("packages").map do |package|
  {
    "name" => package.fetch("name"),
    "version" => package.fetch("version"),
    "license" => package["license"] || "NOASSERTION",
    "source" => package["source"],
    "checksum" => nil
  }
end.sort_by { |package| [package.fetch("name"), package.fetch("version"), package["source"].to_s] }

sbom = {
  "schemaVersion" => 2,
  "generatedAt" => generated_at,
  "sourceRepository" => source_repository,
  "sourceCommit" => source_commit,
  "sourceTree" => source_tree,
  "metadataSha256" => Digest::SHA256.hexdigest(metadata_json),
  "packages" => packages
}

FileUtils.mkdir_p(File.dirname(options[:output]))
File.write(options[:output], JSON.pretty_generate(sbom) + "\n")
puts "sbom=#{options[:output]}"
puts "source_commit=#{source_commit}"
puts "source_tree=#{source_tree}"
puts "workspace_packages=#{packages.length}"

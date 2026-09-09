#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require "digest"
require "optparse"

ROOT = File.expand_path("..", __dir__)
options = {}
OptionParser.new do |parser|
  parser.banner = "usage: verify_rust_apple_artifact.rb --artifact PATH"
  parser.on("--artifact PATH") { |value| options[:artifact] = File.expand_path(value) }
end.parse!

artifact = options.fetch(:artifact)
header = File.join(ROOT, "xray-rust-eval", "crates", "xray-ffi", "include", "xray_ffi.h")
module_map = File.join(ROOT, "xray-rust-eval", "crates", "xray-ffi", "include", "module.modulemap")
errors = []

errors << "artifact directory is missing" unless File.directory?(artifact)
errors << "FFI header is missing" unless File.file?(header)
errors << "module map is missing" unless File.file?(module_map)

header_text = File.file?(header) ? File.read(header) : ""
errors << "ABI major is not 2" unless header_text.include?("#define XRAY_FFI_ABI_MAJOR 2")
errors << "ABI minor is not 0" unless header_text.include?("#define XRAY_FFI_ABI_MINOR 0")

required_slices = {
  "ios-arm64" => File.join(artifact, "ios-arm64", "libxray_ffi.a"),
  "ios-arm64_x86_64-simulator" => File.join(artifact, "ios-arm64_x86_64-simulator", "libxray_ffi.a")
}
required_slices.each do |slice, library|
  errors << "#{slice} library is missing" unless File.file?(library)
end

info_plist = File.join(artifact, "Info.plist")
errors << "XCFramework Info.plist is missing" unless File.file?(info_plist)

if errors.empty?
  puts "rust_apple_artifact=pass"
  puts "header_sha256=#{Digest::SHA256.file(header).hexdigest}"
  puts "module_map_sha256=#{Digest::SHA256.file(module_map).hexdigest}"
  puts "link_symbols=verified_by_build_entrypoint"
  exit 0
end

warn "rust_apple_artifact=fail"
errors.each { |error| warn "- #{error}" }
exit 1

#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

ROOT = File.expand_path("..", __dir__)
errors = []

forbidden_paths = %w[
  apple-wrapper
  upstream
  xray-rust-mobile-eval
  go.work
  go.work.sum
  upstream.lock.yml
  patches/series.yml
  build/folo_build_xcframework.sh
  scripts/check_license_boundary.sh
  scripts/verify_upstream_lock.rb
]
forbidden_paths.each do |relative_path|
  errors << "retired path still exists: #{relative_path}" if File.exist?(File.join(ROOT, relative_path))
end

workflow = File.join(ROOT, ".github", "workflows", "core_ci.yml")
workflow_text = File.file?(workflow) ? File.read(workflow) : ""
%w[apple-wrapper FoloXray FoloXray.xcframework].each do |token|
  errors << "core CI still references #{token}" if workflow_text.include?(token)
end
errors << "Go oracle job is missing" unless workflow_text.include?("go-oracles:")
errors << "core CI still builds Go or cgo runtime" if workflow_text.match?(/\bgo build\b|CGO_ENABLED=1|cgo archive/i)

build = File.join(ROOT, "build", "build_rust_xcframework.sh")
build_text = File.file?(build) ? File.read(build) : ""
errors << "Rust XCFramework build entry is missing" unless File.file?(build)
errors << "Rust XCFramework build does not use xray-ffi" unless build_text.include?("xray-ffi")
errors << "Rust XCFramework build still enables cgo" if build_text.match?(/\bCGO_ENABLED\b|\bgo build\b/)

root_runtime_files = Dir.glob(File.join(ROOT, "{apple-wrapper,upstream}", "**", "*")).select { |path| File.file?(path) }
errors << "retired Go runtime files remain" unless root_runtime_files.empty?

if errors.empty?
  puts "rust_core_boundary=pass"
  exit 0
end

warn "rust_core_boundary=fail"
errors.each { |error| warn "- #{error}" }
exit 1

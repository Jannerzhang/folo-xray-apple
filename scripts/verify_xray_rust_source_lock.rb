#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require "digest"
require "date"
require "English"
require "shellwords"
require "yaml"

ROOT = File.expand_path("..", __dir__)
LOCK_PATH = File.join(ROOT, "compliance", "xray-rust-eval-source-lock.yml")
SOURCE_ROOT = File.join(ROOT, "xray-rust-eval")

def fail!(message)
  warn "xray_rust_source_lock=fail: #{message}"
  exit 1
end

fail!("missing #{LOCK_PATH}") unless File.file?(LOCK_PATH)
lock = YAML.safe_load(File.read(LOCK_PATH), aliases: false)
core = lock.fetch("core")
upstream = lock.fetch("upstreamRust")

actual_commit = `git -C #{ROOT.shellescape} log -1 --format=%H -- xray-rust-eval`.strip
fail!("cannot resolve Rust source commit") unless $CHILD_STATUS.success?
actual_tree = `git -C #{ROOT.shellescape} rev-parse #{actual_commit}:xray-rust-eval`.strip
fail!("cannot resolve xray-rust-eval tree") unless $CHILD_STATUS.success?

fail!("core commit #{actual_commit} != #{core.fetch('commit')}") unless actual_commit == core.fetch("commit")
fail!("Rust source tree #{actual_tree} != #{core.fetch('rustTree')}") unless actual_tree == core.fetch("rustTree")

cargo_lock = File.join(SOURCE_ROOT, "Cargo.lock")
header = File.join(SOURCE_ROOT, "crates", "xray-ffi", "include", "xray_ffi.h")
module_map = File.join(SOURCE_ROOT, "crates", "xray-ffi", "include", "module.modulemap")
marker = File.join(SOURCE_ROOT, "SOURCE_REVISION")
[cargo_lock, header, module_map, marker].each do |path|
  fail!("missing #{path}") unless File.file?(path)
end

fail!("Cargo.lock hash is stale") unless Digest::SHA256.file(cargo_lock).hexdigest == core.fetch("cargoLockSha256")
fail!("FFI header hash is stale") unless Digest::SHA256.file(header).hexdigest == core.fetch("ffi").fetch("headerSha256")
fail!("module map hash is stale") unless Digest::SHA256.file(module_map).hexdigest == core.fetch("ffi").fetch("moduleMapSha256")

marker_text = File.read(marker)
%w[repository tag commit tree].each do |key|
  expected = upstream.fetch(key)
  fail!("SOURCE_REVISION is missing #{key}=#{expected}") unless marker_text.include?("#{key}=#{expected}")
end

header_text = File.read(header)
expected_major = core.fetch("ffi").fetch("abiMajor")
expected_minor = core.fetch("ffi").fetch("abiMinor")
fail!("ABI major is stale") unless header_text.include?("#define XRAY_FFI_ABI_MAJOR #{expected_major}")
fail!("ABI minor is stale") unless header_text.include?("#define XRAY_FFI_ABI_MINOR #{expected_minor}")

puts "xray_rust_source_lock=pass"
puts "core_commit=#{actual_commit}"
puts "rust_tree=#{actual_tree}"

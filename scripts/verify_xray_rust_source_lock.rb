#!/usr/bin/env ruby
# frozen_string_literal: true

# Verifies the immutable source identity used by this evaluation. The source
# lock is intentionally plain text so it can be reviewed without YAML gems.
# When the shallow Git metadata retained by the evaluator is present, the
# commit/tree are checked cryptographically. A source checkout without Git
# metadata is accepted only when its checked-in SOURCE_REVISION marker agrees
# with the lock; artifact release still requires an external provenance review.

require "digest"
require "English"

ROOT = File.expand_path("..", __dir__)
LOCK = File.join(ROOT, "compliance", "xray-rust-eval-source-lock.yml")

EXPECTED = {
  "xray-rust-eval" => {
    repository: "https://github.com/aimalygin/xray-rust.git",
    tag: "v0.5.0",
    commit: "549807d621fadc618e6d0bab75f9e58ef35a7fc1",
    tree: "444c2404cec84f5ff9869af78e403c504b39c161",
    lock_sha: "270d481f84d5e6f8072f6c65988dc2a5f2ef5f9fe7c1055f48c16fe88475ab8a",
    header_sha: "372a5539756df970583b58c3a077363e23dc55b7445b21ecef52ce79b814f952"
  },
  "xray-rust-mobile-eval" => {
    repository: "https://github.com/aimalygin/xray-rust-mobile.git",
    tag: "v0.5.0",
    commit: "377bc2523a97b4faf3b039b65dce2a94381c2e6e",
    tree: "6bb1a2dd97fe0c2df136803a28952561c960da8e",
    header_sha: "0f4753aff311d0d3ec99d00e800814c0adf86860be1fe1f7757b4e217660beb9"
  }
}.freeze

def fail!(message)
  warn "xray_rust_source_lock=fail: #{message}"
  exit 1
end

fail!("missing #{LOCK}") unless File.file?(LOCK)

EXPECTED.each do |directory, expected|
  path = File.join(ROOT, directory)
  marker = File.join(path, "SOURCE_REVISION")
  fail!("missing #{path}") unless File.directory?(path)
  fail!("missing #{marker}") unless File.file?(marker)
  marker_text = File.read(marker)
  expected.each do |key, value|
    next unless %i[repository tag commit tree].include?(key)
    fail!("#{directory} marker #{key}=#{value} missing") unless marker_text.include?("#{key}=#{value}")
  end

  lock_path = directory == "xray-rust-eval" ? File.join(path, "Cargo.lock") : nil
  if expected[:lock_sha]
    fail!("#{directory} Cargo.lock missing") unless File.file?(lock_path)
    actual = Digest::SHA256.file(lock_path).hexdigest
    fail!("#{directory} Cargo.lock hash #{actual}") unless actual == expected[:lock_sha]
  end

  header = if directory == "xray-rust-eval"
             File.join(path, "crates", "xray-ffi", "include", "xray_ffi.h")
           else
             File.join(path, "Sources", "XrayRustFFI", "include", "xray_ffi.h")
           end
  fail!("#{directory} FFI header missing") unless File.file?(header)
  actual_header = Digest::SHA256.file(header).hexdigest
  fail!("#{directory} FFI header hash #{actual_header}") unless actual_header == expected[:header_sha]

  git_dir = File.join(ROOT, ".candidate-#{directory.sub(/-eval\z/, "")}-git")
  next unless File.directory?(git_dir)
  git = lambda do |*args|
    output = IO.popen(["git", "--git-dir", git_dir, "--work-tree", path, *args], &:read)
    fail!("git #{args.join(" ")} failed for #{directory}") unless $CHILD_STATUS&.success?
    output.strip
  end
  actual_commit = git.call("rev-parse", "HEAD")
  actual_tree = git.call("rev-parse", "HEAD^{tree}")
  fail!("#{directory} commit #{actual_commit}") unless actual_commit == expected[:commit]
  fail!("#{directory} tree #{actual_tree}") unless actual_tree == expected[:tree]
end

puts "xray_rust_source_lock=pass"
puts "core_commit=#{EXPECTED["xray-rust-eval"][:commit]}"
puts "mobile_commit=#{EXPECTED["xray-rust-mobile-eval"][:commit]}"

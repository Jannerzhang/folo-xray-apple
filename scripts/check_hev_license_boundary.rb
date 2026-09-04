#!/usr/bin/env ruby
# SPDX-License-Identifier: Apache-2.0

require "digest"
require "yaml"

root = File.expand_path("..", __dir__)
audit_path = File.join(root, "compliance/HEV_CANDIDATE_AUDIT_V1.yml")
approval_path = File.join(root, "compliance/HEV_DEPENDENCY_APPROVAL_V1.yml")
notice_path = File.join(root, "compliance/HEV_THIRD_PARTY_NOTICES.md")
audit = YAML.load_file(audit_path)
approval = YAML.load_file(approval_path)
errors = []
allowed = %w[MIT BSD-3-Clause]

audit.fetch("submodules").each do |component|
  errors << "#{component.fetch('name')}: disallowed license" unless allowed.include?(component.fetch("license"))
  revision = component.fetch("revision")
  errors << "#{component.fetch('name')}: revision is not a commit" unless revision.match?(/\A[0-9a-f]{40}\z/)
  errors << "#{component.fetch('name')}: missing source URL" unless component.fetch("repository").start_with?("https://github.com/")
end

candidate = audit.fetch("candidate")
errors << "candidate: revision is not a commit" unless candidate.fetch("revision").match?(/\A[0-9a-f]{40}\z/)
errors << "candidate: license is not allowed" unless candidate.fetch("license") == "MIT"
errors << "candidate: source URL is not pinned" unless candidate.fetch("repository").start_with?("https://github.com/")
errors << "candidate: Apple utun backend was not excluded" unless audit.fetch("buildBoundary").fetch("excludedPaths").include?("src/hev-tunnel-macos.c")
errors << "candidate: Wintun was not excluded" unless audit.fetch("buildBoundary").fetch("excludedPaths").include?("third-part/wintun")

approval.fetch("components").each do |component|
  errors << "#{component.fetch('name')}: approval revision is not a commit" unless component.fetch("version").match?(/\A[0-9a-f]{40}\z/)
  errors << "#{component.fetch('name')}: approval license is not allowed" unless allowed.include?(component.fetch("spdx"))
  errors << "#{component.fetch('name')}: approval source revision mismatch" unless component.fetch("version") == component.fetch("source").fetch("revision")
end

unless File.read(notice_path).include?("Hev evaluation") && File.read(notice_path).include?("utun backend")
  errors << "third-party notice is incomplete"
end

if errors.empty?
  puts "hev_license_boundary=pass components=#{approval.fetch('components').length} excluded=#{approval.fetch('excludedInputs').length}"
else
  warn errors.join("\n")
  exit 1
end

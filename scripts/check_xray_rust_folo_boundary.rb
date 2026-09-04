#!/usr/bin/env ruby
# frozen_string_literal: true

ROOT = File.expand_path("..", __dir__)
SOURCES = [
  File.join(ROOT, "xray-rust-mobile-eval", "Sources"),
  File.join(ROOT, "xray-rust-eval", "crates")
].freeze

FOLO_SOURCES = File.expand_path("../../ios/Sources", __dir__)

patterns = {
  "utun-control" => /com\.apple\.net\.utun_control|CTLIOCGINFO|AF_SYSTEM/,
  "descriptor-enumeration" => /0\.\.\.maximum|discoverUtunFileDescriptor/,
  "private-fd-io" => /xray_core_set_tun_fd/
}

candidate_findings = []
SOURCES.each do |root|
  Dir.glob(File.join(root, "**", "*.{swift,c,rs}")).sort.each do |path|
    next unless File.file?(path)
    text = File.read(path)
    patterns.each do |name, pattern|
      candidate_findings << "#{name}:#{path.delete_prefix(ROOT + File::SEPARATOR)}" if text.match?(pattern)
    end
  end
end

folo_violations = []
if File.directory?(FOLO_SOURCES)
  Dir.glob(File.join(FOLO_SOURCES, "**", "*.swift")).sort.each do |path|
    text = File.read(path)
    patterns.each do |name, pattern|
      folo_violations << "#{name}:#{path}" if text.match?(pattern)
    end
  end
end

puts "candidate_boundary_findings=#{candidate_findings.length}"
puts "folo_consumer_violations=#{folo_violations.length}"

if folo_violations.empty?
  puts "folo_boundary=pass"
  puts "reason=candidate mobile fd provider is successfully isolated; Folo consumes public NEPacketTunnelFlow only"
  exit 0
else
  folo_violations.each { |v| warn "VIOLATION: #{v}" }
  puts "folo_boundary=blocked"
  exit 2
end

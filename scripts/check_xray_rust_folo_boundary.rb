#!/usr/bin/env ruby
# frozen_string_literal: true

ROOT = File.expand_path("..", __dir__)
SOURCES = [
  File.join(ROOT, "xray-rust-mobile-eval", "Sources"),
  File.join(ROOT, "xray-rust-eval", "crates")
].freeze

patterns = {
  "utun-control" => /com\.apple\.net\.utun_control|CTLIOCGINFO|AF_SYSTEM/,
  "descriptor-enumeration" => /0\.\.\.maximum|discoverUtunFileDescriptor/,
  "private-fd-io" => /getpeername|getsockopt|xray_core_set_tun_fd/
}
findings = []
SOURCES.each do |root|
  Dir.glob(File.join(root, "**", "*.{swift,c,rs}")).sort.each do |path|
    next unless File.file?(path)
    text = File.read(path)
    patterns.each do |name, pattern|
      findings << "#{name}:#{path.delete_prefix(ROOT + File::SEPARATOR)}" if text.match?(pattern)
    end
  end
end

puts "folo_boundary_findings=#{findings.length}"
findings.sort.each { |finding| puts "finding=#{finding}" }
puts "folo_boundary=blocked"
puts "reason=candidate mobile provider contains fd-backed utun discovery; Folo requires public NEPacketTunnelFlow"
exit 2

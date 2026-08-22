#!/usr/bin/env ruby
# SPDX-License-Identifier: Apache-2.0

require "digest"
require "yaml"

root = File.expand_path("..", __dir__)
lock = if YAML.respond_to?(:safe_load_file)
  YAML.safe_load_file(File.join(root, "upstream.lock.yml"), permitted_classes: [Date, Time])
elsif YAML.method(:load_file).parameters.any? { |type, name| name == :permitted_classes }
  YAML.load_file(File.join(root, "upstream.lock.yml"), permitted_classes: [Date, Time])
else
  YAML.load_file(File.join(root, "upstream.lock.yml"))
end
errors = []

def tree_digest(path)
  entries = Dir.glob(File.join(path, "**", "*"), File::FNM_DOTMATCH)
                 .reject { |entry| entry.end_with?("/.") || entry.end_with?("/..") }
                 .reject { |entry| File.directory?(entry) }
                 .sort
  lines = entries.map do |entry|
    relative = entry[(path.length + 1)..-1]
    stat = File.lstat(entry)
    content_hash =
      if stat.symlink?
        Digest::SHA256.hexdigest(File.readlink(entry))
      else
        Digest::SHA256.file(entry).hexdigest
      end
    format("%o\t%s\t%s", stat.mode & 0o7777, relative, content_hash)
  end
  Digest::SHA256.hexdigest(lines.join("\n") + "\n")
end

components = lock.fetch("baseline").fetch("components")
components.each do |component|
  path = File.join(root, component.fetch("importedPath"))
  unless Dir.exist?(path)
    errors << "#{component.fetch('id')}: missing #{path}"
    next
  end

  actual_count = Dir.glob(File.join(path, "**", "*"), File::FNM_DOTMATCH)
                   .reject { |entry| entry.end_with?("/.") || entry.end_with?("/..") }
                   .reject { |entry| File.directory?(entry) }
                   .length
  expected_count = component.fetch("fileCount")
  errors << "#{component.fetch('id')}: file count #{actual_count} != #{expected_count}" unless actual_count == expected_count

  actual_tree = tree_digest(path)
  expected_tree = component.fetch("patchedTreeDigest")
  errors << "#{component.fetch('id')}: tree digest #{actual_tree} != #{expected_tree}" unless actual_tree == expected_tree

  license_file = File.join(root, component.fetch("license").fetch("file"))
  unless File.file?(license_file)
    errors << "#{component.fetch('id')}: missing license file #{license_file}"
    next
  end
  actual_license = Digest::SHA256.file(license_file).hexdigest
  expected_license = component.fetch("license").fetch("sha256")
  errors << "#{component.fetch('id')}: license hash mismatch" unless actual_license == expected_license
end

if errors.empty?
  puts "upstream_lock=pass components=#{components.length}"
else
  warn errors.join("\n")
  exit 1
end

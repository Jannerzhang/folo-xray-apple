#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require "fileutils"
require "openssl"
require "optparse"

options = {}
OptionParser.new do |parser|
  parser.banner = "usage: sign_release_artifact.rb --artifact PATH --private-key PATH --signature PATH"
  parser.on("--artifact PATH") { |value| options[:artifact] = value }
  parser.on("--private-key PATH") { |value| options[:private_key] = value }
  parser.on("--signature PATH") { |value| options[:signature] = value }
end.parse!

artifact = options.fetch(:artifact)
private_key_path = options.fetch(:private_key)
signature_path = options.fetch(:signature)
abort "artifact does not exist" unless File.file?(artifact)
abort "private key does not exist" unless File.file?(private_key_path)

key = OpenSSL::PKey.read(File.read(private_key_path))
abort "private key is not private" unless key.private?

FileUtils.mkdir_p(File.dirname(signature_path))
signature = key.sign(OpenSSL::Digest::SHA256.new, File.binread(artifact))
File.binwrite(signature_path, signature)

puts "artifact_signature=pass"
puts "signature=#{signature_path}"

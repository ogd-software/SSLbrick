# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'sslbrick/version'

Gem::Specification.new do |spec|
  spec.name          = "sslbrick"
  spec.version       = Sslbrick::VERSION
  spec.authors       = ["OGD Software\n"]
  spec.email         = ["software@ogd.nl"]

  spec.summary       = %q{SSL WEBrick handler}
  spec.description   = %q{Modified copy of the standard WEBrick handler with options to force SSL}
  spec.homepage      = "https://github.com/ogd-software/SSLbrick"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rack"
end

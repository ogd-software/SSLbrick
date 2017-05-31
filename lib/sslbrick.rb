require 'webrick'
require 'webrick/https'
require 'stringio'

module Rack
  module Handler
    class SslBrick < ::WEBrick::HTTPServlet::AbstractServlet

      def self.run(app, options={})
        environment  = ENV['RACK_ENV'] || 'development'
        default_host = environment == 'development' ? 'localhost' : nil
        options[:BindAddress] = options.delete(:Host) || default_host
        options[:Port] ||= 8080
        options[:SSLEnable] = true
        options[:SSLCertName] = [['CN', 'localhost']]
        options[:SSLCertComment] = 'SSL Brick self signed certificate'
        # Customized self signed certificate as work around for limitations of serial being reused
        cert, key = create_self_signed_cert(1024, options[:SSLCertName], options[:SSLCertComment])
        options[:SSLCertificate] = cert
        options[:SSLPrivateKey] = key
        @server = ::WEBrick::HTTPServer.new(options)
        @server.mount "/", Rack::Handler::WEBrick, app
        yield @server  if block_given?
        @server.start
      end

      def self.valid_options
        environment  = ENV['RACK_ENV'] || 'development'
        default_host = environment == 'development' ? 'localhost' : '0.0.0.0'
        {
          "Host=HOST" => "Hostname to listen on (default: #{default_host})",
          "Port=PORT" => "Port to listen on (default: 8080)",
        }
      end

      def self.shutdown
        @server.shutdown
        @server = nil
      end

      # Modified Webrick utility function.
      # Standard function uses a fixed serial for each cert, which browsers reject when used for multiple certificates
      def self.create_self_signed_cert(bits, cn, comment)
        rsa = OpenSSL::PKey::RSA.new(bits){|p, n|
          case p
            when 0; $stderr.putc "."  # BN_generate_prime
            when 1; $stderr.putc "+"  # BN_generate_prime
            when 2; $stderr.putc "*"  # searching good prime,
            # n = #of try,
            # but also data from BN_generate_prime
            when 3; $stderr.putc "\n" # found good prime, n==0 - p, n==1 - q,
            # but also data from BN_generate_prime
            else;   $stderr.putc "*"  # BN_generate_prime
          end
        }
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = Time.now.to_i
        name = OpenSSL::X509::Name.new(cn)
        cert.subject = name
        cert.issuer = name
        cert.not_before = Time.now
        cert.not_after = Time.now + (365*24*60*60)
        cert.public_key = rsa.public_key
        ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
        ef.issuer_certificate = cert  
        cert.extensions = [
            ef.create_extension("basicConstraints","CA:FALSE"),
            ef.create_extension("keyUsage", "keyEncipherment"),
            ef.create_extension("subjectKeyIdentifier", "hash"),
            ef.create_extension("extendedKeyUsage", "serverAuth"),
            ef.create_extension("nsComment", comment),
        ]
        aki = ef.create_extension("authorityKeyIdentifier",
                                  "keyid:always,issuer:always")
        cert.add_extension(aki)
        cert.sign(rsa, OpenSSL::Digest::SHA1.new)
        return [ cert, rsa ]
      end

      def initialize(server, app)
        super server
        @app = app
      end

      def service(req, res)
        res.rack = true
        env = req.meta_vars
        env.delete_if { |k, v| v.nil? }
        rack_input = StringIO.new(req.body.to_s)
        rack_input.set_encoding(Encoding::BINARY)
        env.update(
          RACK_VERSION      => Rack::VERSION,
          RACK_INPUT        => rack_input,
          RACK_ERRORS       => $stderr,
          RACK_MULTITHREAD  => true,
          RACK_MULTIPROCESS => false,
          RACK_RUNONCE      => false,
          RACK_URL_SCHEME   => ["yes", "on", "1"].include?(env[HTTPS]) ? "https" : "http",
          RACK_IS_HIJACK    => true,
          RACK_HIJACK       => lambda { raise NotImplementedError, "only partial hijack is supported."},
          RACK_HIJACK_IO    => nil
        )
        env[HTTP_VERSION] ||= env[SERVER_PROTOCOL]
        env[QUERY_STRING] ||= ""
        unless env[PATH_INFO] == ""
          path, n = req.request_uri.path, env[SCRIPT_NAME].length
          env[PATH_INFO] = path[n, path.length-n]
        end
        env[REQUEST_PATH] ||= [env[SCRIPT_NAME], env[PATH_INFO]].join
        status, headers, body = @app.call(env)
        begin
          res.status = status.to_i
          headers.each { |k, vs|
            next if k.downcase == RACK_HIJACK
            if k.downcase == "set-cookie"
              res.cookies.concat vs.split("\n")
            else
              # Since WEBrick won't accept repeated headers,
              # merge the values per RFC 1945 section 4.2.
              res[k] = vs.split("\n").join(", ")
            end
          }
          io_lambda = headers[RACK_HIJACK]
          if io_lambda
            rd, wr = IO.pipe
            res.body = rd
            res.chunked = true
            io_lambda.call wr
          elsif body.respond_to?(:to_path)
            res.body = ::File.open(body.to_path, 'rb')
          else
            body.each { |part|
              res.body << part
            }
          end
        ensure
          body.close  if body.respond_to? :close
        end
      end
    end
  end
end
Rack::Handler.register('sslbrick', Rack::Handler::SslBrick)

{% if flag?(:use_openssl) %}
  require "openssl"
{% else %}
  require "beryl"
{% end %}

# TLS for a MySQL connection.
#
# By default it runs on Beryl: TLS 1.3 only, in Crystal, with no OpenSSL
# linked. A build made with `-Duse_openssl` uses the standard library's
# OpenSSL instead; that flag is kept for one release for servers that cannot
# speak TLS 1.3.
module MySql::TLS
  {% if flag?(:use_openssl) %}
    alias Context = OpenSSL::SSL::Context::Client
    alias Socket = OpenSSL::SSL::Socket::Client

    def self.build_context(options : Connection::SSLOptions) : Context
      context = Context.new
      context.verify_mode = verifies_chain?(options) ? OpenSSL::SSL::VerifyMode::PEER : OpenSSL::SSL::VerifyMode::NONE
      if client_certificate = client_certificate_paths(options)
        cert, key = client_certificate
        context.certificate_chain = cert.to_s
        context.private_key = key.to_s
      end
      if ca = options.ca
        context.ca_certificates = ca.to_s
      end
      context
    end

    def self.connect(io : IO, context : Context, hostname : String?, transport : URI) : Socket
      Socket.new(io, context: context, sync_close: true, hostname: hostname)
    end
  {% else %}
    alias Context = Beryl::TLS::Context::Client
    alias Socket = Beryl::TLS::Socket::Client

    # The alerts a server sends, or the client raises, when the two share no
    # protocol version: a server that stops at TLS 1.2 answers a TLS 1.3
    # ClientHello with one of these.
    LIST_OF_VERSION_ALERTS = [
      Beryl::TLS::AlertDescription::ProtocolVersion,
      Beryl::TLS::AlertDescription::HandshakeFailure,
      Beryl::TLS::AlertDescription::InsufficientSecurity,
    ]

    def self.build_context(options : Connection::SSLOptions) : Context
      context = Context.new
      load_client_certificate(context, options)
      unless verifies_chain?(options)
        context.verify_mode = Beryl::TLS::VerifyMode::None
        return context
      end

      ca = options.ca
      trust_store = ca ? Beryl::Certificates::TrustStore.from_pem(File.read(ca)) : Beryl::Certificates::TrustStore.system
      if options.mode.verify_ca?
        # verify_ca checks the chain and not the name, so the handshake runs
        # with no name to check and this verifier in place of the default.
        context.verify_mode = Beryl::TLS::VerifyMode::None
        context.certificate_verifier = ChainOnlyVerifier.new(trust_store)
      else
        context.verify_mode = Beryl::TLS::VerifyMode::Peer
        context.trust_store = trust_store
      end
      context
    end

    # Sets the certificate chain and key the client presents when the server
    # asks for one (a MySQL account created with REQUIRE X509, SUBJECT or
    # ISSUER). Applies in every ssl-mode, since the server asks for it
    # whatever the client checks.
    private def self.load_client_certificate(context : Context, options : Connection::SSLOptions) : Nil
      client_certificate = client_certificate_paths(options)
      return unless client_certificate

      cert, key = client_certificate
      begin
        context.certificate_chain = cert.to_s
        context.private_key = key.to_s
      rescue error : File::Error | Beryl::Error
        raise Connection::PacketError.new("could not load the client certificate (ssl-cert=#{cert}, ssl-key=#{key}): #{error.message}")
      end
    end

    # Verifies the server's chain to *trust_store* (RFC 5280 path
    # validation, the serverAuth purpose) without checking its name.
    class ChainOnlyVerifier < Beryl::TLS::CertificateVerifier
      def initialize(trust_store : Beryl::Certificates::TrustStore)
        @verifier = Beryl::TLS::WebPkiVerifier.new(trust_store)
      end

      def verify_chain(chain : Array(Beryl::Certificates::Certificate), hostname : String?) : Nil
        @verifier.verify_chain(chain, nil)
      end
    end

    # Runs the TLS handshake over *io* and returns the protected socket.
    # Raises `Connection::PacketError` naming what failed; a server that
    # cannot speak TLS 1.3 gets an error that says so.
    def self.connect(io : IO, context : Context, hostname : String?, transport : URI) : Socket
      Socket.new(io, context: context, sync_close: true, hostname: hostname)
    rescue error : Beryl::TLS::CertificateRejected
      raise Connection::PacketError.new("the MySQL server at #{transport.host}:#{transport.port} sent a certificate that did not verify: #{error.message}")
    rescue error : Beryl::TLS::Error
      if LIST_OF_VERSION_ALERTS.includes?(error.alert_description)
        raise Connection::PacketError.new(
          "the MySQL server at #{transport.host}:#{transport.port} did not agree to TLS 1.3 (#{error.message}). " \
          "This driver connects over TLS 1.3 only; enable TLS 1.3 on the server " \
          "(tls_version = TLSv1.3, MySQL 8.0.16 or later), or connect with ssl-mode=disabled on a trusted network")
      end
      raise Connection::PacketError.new("the TLS handshake with the MySQL server at #{transport.host}:#{transport.port} failed: #{error.message}")
    end
  {% end %}

  # The client certificate and key paths, or nil when neither is given.
  # Raises `Connection::PacketError` naming the missing one when only one is.
  private def self.client_certificate_paths(options : Connection::SSLOptions) : {Path, Path}?
    cert = options.cert
    key = options.key
    if cert && key
      {cert, key}
    elsif cert
      raise Connection::PacketError.new("ssl-cert was given without ssl-key; a client certificate needs both (add ssl-key=<path to the client key>)")
    elsif key
      raise Connection::PacketError.new("ssl-key was given without ssl-cert; a client certificate needs both (add ssl-cert=<path to the client certificate>)")
    end
  end

  private def self.verifies_chain?(options : Connection::SSLOptions) : Bool
    options.mode.verify_ca? || options.mode.verify_identity?
  end
end

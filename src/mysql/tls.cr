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
      if cert = options.cert
        context.certificate_chain = cert.to_s
      end
      if key = options.key
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
      if options.cert || options.key
        raise Connection::PacketError.new(
          "ssl-cert and ssl-key (client certificates) are not supported by Beryl TLS; " \
          "build with -Duse_openssl to use them")
      end

      context = Context.new
      if verifies_chain?(options)
        context.verify_mode = Beryl::TLS::VerifyMode::Peer
        if ca = options.ca
          context.ca_certificates = ca.to_s
        else
          context.trust_store = Beryl::Certificates::TrustStore.system
        end
      else
        context.verify_mode = Beryl::TLS::VerifyMode::None
      end
      context
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

  private def self.verifies_chain?(options : Connection::SSLOptions) : Bool
    options.mode.verify_ca? || options.mode.verify_identity?
  end
end

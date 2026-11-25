require "./spec_helper"

private def from_uri(uri)
  Connection::Options.from_uri(URI.parse(uri))
end

private def tcp(host, port)
  URI.new("tcp", host, port)
end

private def socket(path)
  URI.new("unix", nil, nil, path)
end

private def ssl_from_params(params)
  Connection::SSLOptions.from_params(URI::Params.parse(params))
end

SSL_OPTION_PREFERRED = Connection::SSLOptions.new(mode: :preferred)

# A throwaway client certificate and key (EC P-256), made once with the
# openssl command line tool in a temporary folder, so no private key is
# kept in the repository. Returns {certificate path, key path}.
private def client_certificate_files : {String, String}
  dir = File.join(Dir.tempdir, "crystal-mysql-spec-client-#{Process.pid}")
  cert = File.join(dir, "client.pem")
  key = File.join(dir, "client.key")
  unless File.exists?(cert) && File.exists?(key)
    Dir.mkdir_p(dir)
    status = Process.run("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                                     "-days", "1", "-subj", "/CN=crystal-mysql spec client", "-keyout", key, "-out", cert],
      output: Process::Redirect::Close, error: Process::Redirect::Inherit)
    raise "openssl could not make the spec client certificate" unless status.success?
  end
  {cert, key}
end

describe Connection::Options do
  describe ".from_uri" do
    it "parses mysql://user@host/db" do
      from_uri("mysql://root@localhost/test").should eq(
        Connection::Options.new(
          transport: tcp("localhost", 3306),
          username: "root",
          password: nil,
          initial_catalog: "test",
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql://host" do
      from_uri("mysql://localhost").should eq(
        Connection::Options.new(
          transport: tcp("localhost", 3306),
          username: nil,
          password: nil,
          initial_catalog: nil,
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql://host:port" do
      from_uri("mysql://localhost:1234").should eq(
        Connection::Options.new(
          transport: tcp("localhost", 1234),
          username: nil,
          password: nil,
          initial_catalog: nil,
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses ?encoding=..." do
      from_uri("mysql://localhost:1234?encoding=utf8mb4_unicode_520_ci").should eq(
        Connection::Options.new(
          transport: tcp("localhost", 1234),
          username: nil,
          password: nil,
          initial_catalog: nil,
          charset: "utf8mb4_unicode_520_ci",
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql://user@host?database=db" do
      from_uri("mysql://root@localhost?database=test").should eq(
        Connection::Options.new(
          transport: tcp("localhost", 3306),
          username: "root",
          password: nil,
          initial_catalog: "test",
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql:///path/to/socket" do
      from_uri("mysql:///path/to/socket").should eq(
        Connection::Options.new(
          transport: socket("/path/to/socket"),
          username: nil,
          password: nil,
          initial_catalog: nil,
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql:///path/to/socket?database=test" do
      from_uri("mysql:///path/to/socket?database=test").should eq(
        Connection::Options.new(
          transport: socket("/path/to/socket"),
          username: nil,
          password: nil,
          initial_catalog: "test",
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql:///path/to/socket?encoding=utf8mb4_unicode_520_ci" do
      from_uri("mysql:///path/to/socket?encoding=utf8mb4_unicode_520_ci").should eq(
        Connection::Options.new(
          transport: socket("/path/to/socket"),
          username: nil,
          password: nil,
          initial_catalog: nil,
          charset: "utf8mb4_unicode_520_ci",
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end

    it "parses mysql://user:pass@/path/to/socket?database=test" do
      from_uri("mysql://root:password@/path/to/socket?database=test").should eq(
        Connection::Options.new(
          transport: socket("/path/to/socket"),
          username: "root",
          password: "password",
          initial_catalog: "test",
          charset: Collations.default_collation,
          ssl_options: SSL_OPTION_PREFERRED
        )
      )
    end
  end
end

describe Connection::SSLOptions do
  describe ".from_params" do
    it "default is ssl-mode=preferred" do
      ssl_from_params("").mode.should eq(Connection::SSLMode::Preferred)
    end

    it "parses ssl-mode=preferred" do
      ssl_from_params("ssl-mode=preferred").mode.should eq(Connection::SSLMode::Preferred)
      ssl_from_params("ssl-mode=Preferred").mode.should eq(Connection::SSLMode::Preferred)
      ssl_from_params("ssl-mode=PREFERRED").mode.should eq(Connection::SSLMode::Preferred)
    end

    it "parses ssl-mode=disabled" do
      ssl_from_params("ssl-mode=disabled").mode.should eq(Connection::SSLMode::Disabled)
      ssl_from_params("ssl-mode=Disabled").mode.should eq(Connection::SSLMode::Disabled)
      ssl_from_params("ssl-mode=DISABLED").mode.should eq(Connection::SSLMode::Disabled)
    end

    it "parses ssl-mode=verifyca" do
      ssl_from_params("ssl-mode=verifyca").mode.should eq(Connection::SSLMode::VerifyCA)
      ssl_from_params("ssl-mode=verify-ca").mode.should eq(Connection::SSLMode::VerifyCA)
      ssl_from_params("ssl-mode=verify_ca").mode.should eq(Connection::SSLMode::VerifyCA)
      ssl_from_params("ssl-mode=VERIFY_CA").mode.should eq(Connection::SSLMode::VerifyCA)
    end

    it "parses ssl-mode=verifyidentity" do
      ssl_from_params("ssl-mode=verifyidentity").mode.should eq(Connection::SSLMode::VerifyIdentity)
      ssl_from_params("ssl-mode=verify-identity").mode.should eq(Connection::SSLMode::VerifyIdentity)
      ssl_from_params("ssl-mode=verify_identity").mode.should eq(Connection::SSLMode::VerifyIdentity)
      ssl_from_params("ssl-mode=VERIFY_IDENTITY").mode.should eq(Connection::SSLMode::VerifyIdentity)
    end

    it "parses ssl-key, ssl-cert, ssl-ca" do
      ssl_from_params("ssl-key=path/to/key.pem&ssl-cert=path/to/cert.pem&ssl-ca=path/to/ca.pem").should eq(
        Connection::SSLOptions.new(mode: Connection::SSLMode::Preferred,
          key: Path["path/to/key.pem"].expand(home: true),
          cert: Path["path/to/cert.pem"].expand(home: true),
          ca: Path["path/to/ca.pem"].expand(home: true))
      )
    end

    it "missing ssl-key, ssl-cert, ssl-ca as nil" do
      ssl_from_params("").should eq(
        Connection::SSLOptions.new(mode: Connection::SSLMode::Preferred,
          key: nil,
          cert: nil,
          ca: nil)
      )
    end
  end

  describe "#tls_hostname" do
    it "sends and checks the host for every mode but verify_ca" do
      ssl_from_params("ssl-mode=verify_identity").tls_hostname("db.example.com").should eq("db.example.com")
      ssl_from_params("ssl-mode=required").tls_hostname("db.example.com").should eq("db.example.com")
    end

    it "checks the chain only for verify_ca" do
      ssl_from_params("ssl-mode=verify_ca").tls_hostname("db.example.com").should be_nil
    end
  end

  {% unless flag?(:use_openssl) %}
    describe "#build_context" do
      it "skips chain verification for preferred and required" do
        ssl_from_params("ssl-mode=required").build_context.verify_mode.should eq(Beryl::TLS::VerifyMode::None)
      end

      it "verifies against the CA file given for verify_ca" do
        ca = File.join(__DIR__, "fixtures", "ca_certificate.pem")
        context = ssl_from_params("ssl-mode=verify_ca&ssl-ca=#{ca}").build_context
        context.verify_mode.should eq(Beryl::TLS::VerifyMode::None)
        context.certificate_verifier.should be_a(MySql::TLS::ChainOnlyVerifier)
      end

      it "loads the client certificate and key in every ssl-mode" do
        ca = File.join(__DIR__, "fixtures", "ca_certificate.pem")
        cert, key = client_certificate_files
        expected_chain = Beryl::Certificates.read_pem_chain(File.read(cert))
        {"preferred", "required", "verify_ca", "verify_identity"}.each do |mode|
          context = ssl_from_params("ssl-mode=#{mode}&ssl-ca=#{ca}&ssl-cert=#{cert}&ssl-key=#{key}").build_context
          certified_key = context.certified_key?
          certified_key.should_not be_nil, "no client certificate for ssl-mode=#{mode}"
          if certified_key
            certified_key.list_of_certificates.map(&.encoded).should eq(expected_chain.map(&.encoded))
          end
        end
      end

      it "keeps the chain-only verifier for verify_ca with a client certificate" do
        ca = File.join(__DIR__, "fixtures", "ca_certificate.pem")
        cert, key = client_certificate_files
        context = ssl_from_params("ssl-mode=verify_ca&ssl-ca=#{ca}&ssl-cert=#{cert}&ssl-key=#{key}").build_context
        context.certificate_verifier.should be_a(MySql::TLS::ChainOnlyVerifier)
        context.certified_key?.should_not be_nil
      end

      it "presents no client certificate when neither ssl-cert nor ssl-key is given" do
        ssl_from_params("ssl-mode=required").build_context.certified_key?.should be_nil
      end

      it "names the file when the client certificate cannot be read" do
        _, key = client_certificate_files
        expect_raises(Connection::PacketError, /could not load the client certificate \(ssl-cert=\/nonexistent\/client\.pem/) do
          ssl_from_params("ssl-mode=required&ssl-cert=/nonexistent/client.pem&ssl-key=#{key}").build_context
        end
      end
    end
  {% end %}

  describe "client certificate parameters" do
    it "names ssl-key when only ssl-cert is given" do
      expect_raises(Connection::PacketError, "ssl-cert was given without ssl-key") do
        ssl_from_params("ssl-mode=required&ssl-cert=client.pem").build_context
      end
    end

    it "names ssl-cert when only ssl-key is given" do
      expect_raises(Connection::PacketError, "ssl-key was given without ssl-cert") do
        ssl_from_params("ssl-mode=verify_ca&ssl-key=client.key").build_context
      end
    end
  end
end

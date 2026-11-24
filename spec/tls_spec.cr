require "./spec_helper"

# Live checks of TLS and of the password exchanges that depend on it. They
# need the server named by DATABASE_HOST (root with no password, as the rest
# of the suite). Optional settings:
#
# - MYSQL_TLS_CA: the CA file that signed the server's certificate, whose
#   names include DATABASE_HOST; enables the verify_ca and verify_identity
#   examples.
# - MYSQL_TLS12_URL: a server that offers TLS 1.2 only; enables the example
#   that expects the TLS 1.3 error.

private def ssl_version(db : DB::Database) : String
  db.query_one("SHOW SESSION STATUS LIKE 'Ssl_version'", as: {String, String})[1]
end

private def tcp_host? : Bool
  !database_host.starts_with?("/")
end

private def password_user_url(params : String) : String
  "mysql://m3_password_user:m3%20secret@#{database_host}?#{params}"
end

private def with_password_user(&)
  DB.open db_url do |db|
    db.exec "DROP USER IF EXISTS 'm3_password_user'@'%'"
    db.exec "CREATE USER 'm3_password_user'@'%' IDENTIFIED WITH caching_sha2_password BY 'm3 secret'"
  end
  yield
ensure
  DB.open db_url do |db|
    db.exec "DROP USER IF EXISTS 'm3_password_user'@'%'"
  end
end

# Empties the server's caching_sha2_password cache, so the next login with a
# password takes the full-authentication path.
private def flush_password_cache
  DB.open db_url do |db|
    db.exec "FLUSH PRIVILEGES"
  end
end

describe "TLS" do
  it "negotiates TLS 1.3 by default (ssl-mode=preferred)" do
    pending! "TLS over a UNIX socket is off for preferred" unless tcp_host?
    DB.open db_url do |db|
      ssl_version(db).should eq("TLSv1.3")
    end
  end

  it "runs without TLS for ssl-mode=disabled" do
    DB.open "#{db_url}ssl-mode=disabled" do |db|
      ssl_version(db).should eq("")
    end
  end

  it "verifies the chain for ssl-mode=verify_ca" do
    ca = ENV["MYSQL_TLS_CA"]?.presence || pending!("set MYSQL_TLS_CA to the server's CA file")
    DB.open "#{db_url}ssl-mode=verify_ca&ssl-ca=#{ca}" do |db|
      ssl_version(db).should eq("TLSv1.3")
    end
  end

  it "verifies the chain and the name for ssl-mode=verify_identity" do
    ca = ENV["MYSQL_TLS_CA"]?.presence || pending!("set MYSQL_TLS_CA to the server's CA file")
    DB.open "#{db_url}ssl-mode=verify_identity&ssl-ca=#{ca}" do |db|
      ssl_version(db).should eq("TLSv1.3")
    end
  end

  it "refuses a chain that does not lead to the CA given" do
    pending! "TLS over a UNIX socket is off for preferred" unless tcp_host?
    other_ca = File.join(__DIR__, "fixtures", "ca_certificate.pem")
    expect_raises(Exception, /did not verify|certificate verify failed/) do
      DB.open "#{db_url}ssl-mode=verify_ca&ssl-ca=#{other_ca}" do |db|
        db.scalar("SELECT 1")
      end
    end
  end

  it "names the TLS 1.3 requirement when the server offers TLS 1.2 only" do
    url = ENV["MYSQL_TLS12_URL"]?.presence || pending!("set MYSQL_TLS12_URL to a server limited to TLS 1.2")
    expect_raises(Exception, /TLS 1\.3/) do
      DB.open "#{url}?ssl-mode=required" do |db|
        db.scalar("SELECT 1")
      end
    end
  end
end

describe "caching_sha2_password" do
  it "logs in with full authentication inside TLS, then with the fast path" do
    pending! "TLS over a UNIX socket is off for preferred" unless tcp_host?
    with_password_user do
      flush_password_cache
      2.times do
        DB.open password_user_url("ssl-mode=required") do |db|
          db.scalar("SELECT CURRENT_USER()").as(String).should start_with("m3_password_user@")
          ssl_version(db).should eq("TLSv1.3")
        end
      end
    end
  end

  it "logs in with full authentication over the RSA key exchange without TLS" do
    pending! "the RSA exchange is for TCP; a UNIX socket counts as secure" unless tcp_host?
    with_password_user do
      flush_password_cache
      DB.open password_user_url("ssl-mode=disabled") do |db|
        db.scalar("SELECT CURRENT_USER()").as(String).should start_with("m3_password_user@")
        ssl_version(db).should eq("")
      end
    end
  end

  it "refuses a wrong password" do
    with_password_user do
      expect_raises(Exception, /Access denied/) do
        DB.open "mysql://m3_password_user:wrong@#{database_host}?ssl-mode=required" do |db|
          db.scalar("SELECT 1")
        end
      end
    end
  end
end

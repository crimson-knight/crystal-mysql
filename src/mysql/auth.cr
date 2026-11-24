require "beryl"

# Password hashing and encryption for the MySQL authentication plugins,
# written on Beryl, so they call no OpenSSL.
module MySql::Auth
  private alias SHA1 = Beryl::Crypto::Compatibility::SHA1

  def self.compute_auth_response(plugin_name : String, password : String?, scramble : Bytes, ssl_established : Bool = false) : Bytes
    if password.nil? || password.empty?
      return Bytes.empty
    end

    case plugin_name
    when "mysql_native_password"
      native_password(password, scramble)
    when "caching_sha2_password"
      caching_sha2_password(password, scramble)
    when "sha256_password"
      if ssl_established
        # Over TLS: send plaintext password null-terminated
        clear_password(password)
      else
        # Without TLS: send 0x01 to request RSA public key
        Bytes[0x01]
      end
    when "mysql_clear_password"
      clear_password(password)
    else
      raise MySql::Connection::PacketError.new("Unsupported auth plugin: #{plugin_name}")
    end
  end

  def self.native_password(password : String, scramble : Bytes) : Bytes
    sha1 = SHA1.digest(password)
    sha1sha1 = SHA1.digest(sha1)

    buffer = Bytes.new(40)
    buffer[0, 20].copy_from(scramble[0, 20])
    buffer[20, 20].copy_from(sha1sha1)

    buffer_sha1 = SHA1.digest(buffer)

    result = Bytes.new(20)
    20.times { |i| result[i] = sha1[i] ^ buffer_sha1[i] }
    result
  end

  def self.caching_sha2_password(password : String, scramble : Bytes) : Bytes
    hash1 = sha256(password.to_slice)
    hash2 = sha256(hash1)

    concat = Bytes.new(hash2.size + scramble.size)
    concat[0, hash2.size].copy_from(hash2)
    concat[hash2.size, scramble.size].copy_from(scramble)
    hash3 = sha256(concat)

    result = Bytes.new(32)
    32.times { |i| result[i] = hash1[i] ^ hash3[i] }
    result
  end

  def self.clear_password(password : String) : Bytes
    bytes = Bytes.new(password.bytesize + 1)
    bytes[0, password.bytesize].copy_from(password.to_slice)
    bytes[password.bytesize] = 0_u8
    bytes
  end

  def self.xor_password_scramble(password : String, scramble : Bytes) : Bytes
    pass_bytes = password.to_slice
    result = Bytes.new(pass_bytes.size + 1)
    pass_bytes.size.times do |i|
      result[i] = pass_bytes[i] ^ scramble[i % scramble.size]
    end
    # XOR the null terminator too (matches MySQL protocol spec)
    result[pass_bytes.size] = 0_u8 ^ scramble[pass_bytes.size % scramble.size]
    result
  end

  # Encrypts the password for the server holding the RSA public key in
  # *pem_key* (a `PUBLIC KEY` block), as caching_sha2_password and
  # sha256_password do over a connection without TLS: the password, NUL
  # terminated and XORed with the scramble, under RSAES-OAEP with SHA-1 and
  # MGF1-SHA-1, which is what the server decrypts with.
  def self.rsa_encrypt_password(password : String, scramble : Bytes, pem_key : String) : Bytes
    public_key = read_rsa_public_key(pem_key)
    public_key.encrypt_with_oaep(xor_password_scramble(password, scramble), hash_function: SHA1)
  rescue error : Beryl::Error
    raise Connection::PacketError.new("RSA encryption of the password failed: #{error.message}")
  end

  # Reads the server's RSA public key from its PEM `PUBLIC KEY` block.
  def self.read_rsa_public_key(pem_key : String) : Beryl::Crypto::V1::RSA::PublicKey
    der = Beryl::Encoding::PEM.decode(pem_key, label: "PUBLIC KEY").first? ||
          raise Connection::PacketError.new("the server sent no PUBLIC KEY block")
    public_key = Beryl::Certificates::SubjectPublicKeyInfo.from_der(der).verification_key
    unless public_key.is_a?(Beryl::Crypto::V1::RSA::PublicKey)
      raise Connection::PacketError.new("the server public key is not an RSA key")
    end
    public_key
  end

  private def self.sha256(data : Bytes) : Bytes
    Beryl::Crypto::V1::SHA256.digest(data)
  end
end

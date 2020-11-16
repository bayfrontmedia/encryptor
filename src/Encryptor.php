<?php

/**
 * @package encryptor
 * @link https://github.com/bayfrontmedia/encryptor
 * @author John Robinson <john@bayfrontmedia.com>
 * @copyright 2020 Bayfront Media
 */

namespace Bayfront\Encryptor;

class Encryptor
{

    protected $key;
    protected $cipher;

    /**
     * Encrypt constructor.
     *
     * @param string $key (Encryption key)
     * @param string $cipher (Encryption algorithm)
     *
     * @throws InvalidCipherException
     */

    public function __construct(string $key, string $cipher = 'AES-256-CBC')
    {

        /*
         * Ensure openssl_get_cipher_methods() returns uppercase values
         * (OpenSSL 1.1.1 does not)
         */

        if (!in_array(strtoupper($cipher), array_map('strtoupper', openssl_get_cipher_methods()))) {
            throw new InvalidCipherException('Invalid cipher method: ' . $cipher);
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

    /**
     * Create a single-use random Initialization Vector.
     *
     * @return string
     *
     * @throws EncryptException
     */

    protected function _createIv()
    {

        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));

        if (false === $iv) {
            throw new EncryptException('Unable to create Initialization Vector');
        }

        return $iv;
    }

    /**
     * Returns the encryption key.
     *
     * @return string
     */

    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Returns the cipher method used for encryption.
     *
     * @return string
     */

    public function getCipher(): string
    {
        return $this->cipher;
    }

    /**
     * Create a MAC for a given value.
     *
     * @param string $iv
     * @param mixed $value
     *
     * @return string
     */

    protected function _createHash(string $iv, $value): string
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }

    /**
     * Encrypts a given value.
     *
     * @param mixed $value
     * @param bool $serialize
     *
     * @return string
     *
     * @throws EncryptException
     */

    public function encrypt($value, bool $serialize = true): string
    {

        if (true === $serialize) {

            $value = serialize($value);

        }

        // Single-use random Initialization Vector

        $iv = $this->_createIv();

        // Encrypted value

        $value = openssl_encrypt($value, $this->cipher, $this->key, 0, $iv);

        if (false === $value) {
            throw new EncryptException('Unable to encrypt value');
        }

        // With value encrypted, create a hash used to verify its authenticity when decrypting

        $iv = base64_encode($iv);

        $hash = $this->_createHash($iv, $value);

        $json = json_encode([
            'iv' => $iv,
            'value' => $value,
            'hash' => $hash
        ], JSON_UNESCAPED_SLASHES);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Unable to encrypt value');
        }

        return base64_encode($json);

    }

    /**
     * Encrypts a string without serialization.
     *
     * @param string $value
     *
     * @return string
     *
     * @throws EncryptException
     */

    public function encryptString(string $value): string
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypts a given value.
     *
     * @param string $data
     * @param bool $unserialize
     *
     * @return mixed
     *
     * @throws DecryptException
     */

    public function decrypt(string $data, bool $unserialize = true)
    {

        $data = json_decode(base64_decode($data), true);

        // Check the validity of the data

        if (!is_array($data)
            || !isset($data['iv'], $data['value'], $data['hash'])
            || strlen(base64_decode($data['iv'], true)) !== openssl_cipher_iv_length($this->cipher)) {
            throw new DecryptException('Unable to decrypt data: invalid data');
        }

        // Check the validity of the hash

        if (!hash_equals($this->_createHash($data['iv'], $data['value']), $data['hash'])) {
            throw new DecryptException('Unable to decrypt data: invalid hash');
        }

        $iv = base64_decode($data['iv']);

        // Attempt to decrypt

        $decrypted = openssl_decrypt($data['value'], $this->cipher, $this->key, 0, $iv);

        if (false === $decrypted) {
            throw new DecryptException('Unable to decrypt data');
        }

        if (true === $unserialize) {
            return unserialize($decrypted);
        }

        return $decrypted;

    }

    /**
     * Decrypts a string without unserialization.
     *
     * @param string $data
     *
     * @return string
     *
     * @throws DecryptException
     */

    public function decryptString(string $data): string
    {
        return $this->decrypt($data, false);
    }

}
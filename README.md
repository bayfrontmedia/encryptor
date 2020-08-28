## Encryptor

A fast, simple two-way encryption library utilizing OpenSSL.

- [License](#license)
- [Author](#author)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)

## License

This project is open source and available under the [MIT License](https://github.com/bayfrontmedia/php-array-helpers/blob/master/LICENSE).

## Author

John Robinson, [Bayfront Media](https://www.bayfrontmedia.com)

## Requirements

* PHP >= 7.1.0
* OpenSSL PHP extension
* JSON PHP extension

## Installation

```
composer require bayfrontmedia/encryptor
```

## Usage

### Start using Encryptor

A private, reproducible key must be passed to the constructor. 
The same key must be used when encrypting and decrypting.
If the key used to encrypt a value is lost, it will not be able to be decrypted.

An optional second constructor parameter allows you to specify which [cipher method](https://www.php.net/manual/en/function.openssl-get-cipher-methods.php) to use.
By default, Encryptor uses `AES-256-CBC`.

If an invalid cipher method is used, a `Bayfront\Encryptor\InvalidCipherException` exception will be thrown.

```
use Bayfront\Encryptor\Encryptor;

$encryptor = new Encryptor('private_key');
```

### Public methods

- [getKey](#getkey)
- [getCipher](#getcipher)
- [encrypt](#encrypt)
- [encryptString](#encryptstring)
- [decrypt](#decrypt)
- [decryptString](#decryptstring)

<hr />

### getKey

**Description:**

Returns the encryption key.

**Parameters:**

- None

**Returns:**

- (string)

<hr />

### getCipher

**Description:**

Returns the cipher method used for encryption.

**Parameters:**

- None

**Returns:**

- (string)

<hr />

### encrypt

**Description:**

Encrypts a given value. 

**Parameters:**

- `$value` (mixed)
- `$serialize = true` (bool)

**Returns:**

- (string)

**Throws:**

- `Bayfront\Encryptor\EncryptException`

**Example:**

```
try {

    $encrypted = $encryptor->encrypt([
        'name' => 'John',
        'user_id' => 8
    ]);

} catch (EncryptException $e) {
    die($e->getMessage());
}
```

<hr />

### encryptString

**Description:**

Encrypts a string without serialization. 

**Parameters:**

- `$value` (string)

**Returns:**

- (string)

**Throws:**

- `Bayfront\Encryptor\EncryptException`

**Example:**

```
try {

    $encrypted_string = $encryptor->encryptString('A string to encrypt');

} catch (EncryptException $e) {
    die($e->getMessage());
}
```

<hr />

### decrypt

**Description:**

Decrypts a given value. 

**Parameters:**

- `$data` (string)
- `$unserialize = true` (bool)

**Returns:**

- (mixed)

**Throws:**

- `Bayfront\Encryptor\DecryptException`

**Example:**

```
try {

    $decrypted = $encryptor->decrypt($encrypted);

} catch (DecryptException $e) {
    die($e->getMessage());
}
```

<hr />

### decryptString

**Description:**

Decrypts a string without unserialization. 

**Parameters:**

- `$data` (string)

**Returns:**

- (string)

**Throws:**

- `Bayfront\Encryptor\DecryptException`

**Example:**

```
try {

    $decrypted_string = $encryptor->decryptString($encrypted_string);

} catch (DecryptException $e) {
    die($e->getMessage());
}
```
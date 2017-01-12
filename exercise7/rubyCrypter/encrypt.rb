#!/usr/bin/env ruby
require 'salsa20'

key = "VERY_SECRET_256_BIT_KEY_12345678"
iv = "-RANDOM-"
plain_text = "Salsa20 is a family of 256-bit stream ciphers"

encryptor = Salsa20.new(key, iv)
encrypted_text = encryptor.encrypt(plain_text)
p encrypted_text

decryptor = Salsa20.new(key, iv)
decrypted_text = decryptor.decrypt(encrypted_text)
p decrypted_text

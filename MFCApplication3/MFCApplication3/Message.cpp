#include "stdafx.h"
#include "Message.h"
#include <stdlib.h>
#include"openssl/bn.h"
#include"openssl/sha.h"
#include"openssl/aes.h"
#include<time.h>
#include<Windows.h>
#include"openssl/dh.h"
#include"openssl/engine.h"
#include"Resource.h"
#include"resource.h"


void Message::send(User *sender, User *receiver, CString title, CString content)
{
	senderID = sender->id;
	receiverID = receiver->id;
	M_title = title;
	M_content = content;

	unsigned char key_char[128];
	unsigned char plain_text[128];
	unsigned char cipher_text[128];
	unsigned char aes_key_1[128];
	AES_KEY aes_key_2;
	
	ZeroMemory(plain_text, sizeof(plain_text));
	memcpy(plain_text, content, content.GetLength());
	
	SHA_CTX sha1;

	p = BN_new();
	g = BN_new();
	ctx = BN_CTX_new();
	key = BN_new();
	sender->public_key = BN_new();
	receiver->public_key = BN_new();

	BN_dec2bn(&p, "5");
	BN_generate_prime(g, 512, 0, 0, NULL, NULL, NULL);

	sender->mk_public_key(g, p,ctx);
	receiver->mk_public_key(g, p, ctx);
	sender->mk_key(key, receiver->public_key, p, ctx);

	BN_bn2bin(key, key_char);
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, key_char, sizeof(key_char));
	SHA1_Final(aes_key_1, &sha1);
	
	AES_set_encrypt_key(aes_key_1, sizeof(aes_key_1), &aes_key_2);
	AES_encrypt(plain_text, cipher_text, &aes_key_2);

	M_content.Format(_T("%s"), cipher_text);
	
	BN_free(key);
	BN_free(sender->public_key);
	BN_free(receiver->public_key);
	BN_CTX_free(ctx);

}

void Message::lookup(User * sender, User * receiver)
{
	unsigned char key_char[128];
	unsigned char plain_text[128];
	unsigned char cipher_text[128];
	BIGNUM *this_key = BN_new();
	SHA_CTX sha1;
	unsigned char aes_key_1[128];
	AES_KEY aes_key_2;

	sender->public_key = BN_new();
	receiver->public_key = BN_new();

	ZeroMemory(cipher_text, sizeof(cipher_text));
	memcpy(cipher_text, M_content, M_content.GetLength());
	
	sender->mk_public_key(g, p, ctx);
	receiver->mk_public_key(g, p, ctx);
	sender->mk_key(this_key,receiver->public_key, p, ctx);

	BN_bn2bin(this_key, key_char);
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, key_char, sizeof(key_char));
	SHA1_Final(aes_key_1, &sha1);
	
	AES_set_decrypt_key(aes_key_1, sizeof(aes_key_1), &aes_key_2);
	AES_decrypt(cipher_text, plain_text, &aes_key_2);

	M_dec.Format(_T("%s"), plain_text);
	BN_free(this_key);
	BN_free(sender->public_key);
	BN_free(receiver->public_key);
	BN_CTX_free(ctx);
}

Message::Message()
{
}


Message::~Message()
{
}

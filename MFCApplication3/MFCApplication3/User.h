#pragma once
#include <stdlib.h>
#include"openssl/bn.h"
#include"openssl/sha.h"
#include"openssl/aes.h"
#include<time.h>
#include<Windows.h>
#include"openssl/dh.h"
#include"openssl/engine.h"
class User
{
private:
	
	BIGNUM *private_key;
public:
	unsigned char hashpw[128];
	CString id;
	BIGNUM *public_key;
	void join(CString user_id, CString user_pw);
	bool login(CString input_pw);
	
	void mk_public_key(BIGNUM *g, BIGNUM *p, BN_CTX *ctx);
		//BN_mod_exp(public_key_a, g, private_key_a, p, ctx);
	void mk_key(BIGNUM *key, BIGNUM *public_k_a, BIGNUM *p, BN_CTX *ctx);
	//BN_mod_exp(key, g, pblic_key_a, privte_b,p, ctx);
	User();
	~User();
};


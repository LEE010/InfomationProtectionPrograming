#include "stdafx.h"
#include "User.h"
#include <stdlib.h>
#include"openssl/bn.h"
#include"openssl/sha.h"
#include"openssl/aes.h"
#include<time.h>
#include<Windows.h>
#include"openssl/dh.h"
#include"openssl/engine.h"
#include "MFCApplication3.h"
#include "MFCApplication3Doc.h"
#include "MFCApplication3View.h"


void User::join(CString user_id, CString user_pw)
{
	id = user_id;
	SHA_CTX sha1;

	ZeroMemory(hashpw, sizeof(hashpw));

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, user_pw, user_pw.GetLength());
	SHA1_Final(hashpw, &sha1);
	
	private_key = BN_new();

	BN_pseudo_rand(private_key, 512, 0, 1);
}

bool User::login(CString pw)
{
	unsigned char submit_pw[128];
	SHA_CTX sha1;

	ZeroMemory(submit_pw, 128);
	
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, pw, pw.GetLength());
	SHA1_Final(submit_pw, &sha1);

	if (strcmp((LPSTR)submit_pw, (LPSTR)hashpw)==0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
	
}

void User::mk_public_key(BIGNUM * g, BIGNUM * p, BN_CTX * ctx)
{
	BN_mod_exp(public_key, g, private_key, p, ctx);
}

void User::mk_key(BIGNUM * key, BIGNUM * public_k, BIGNUM * p, BN_CTX * ctx)
{
	BN_mod_exp(key, public_k, private_key, p, ctx);
}

User::User()
{
}


User::~User()
{
}

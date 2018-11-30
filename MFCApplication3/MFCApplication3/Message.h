#pragma once
#include "User.h"
#include <stdlib.h>
#include"openssl/bn.h"
#include"openssl/sha.h"
#include"openssl/aes.h"
#include<time.h>
#include<Windows.h>
#include"openssl/dh.h"
#include"openssl/engine.h"
class Message :
	public User
	

{
private:
	BIGNUM * key;
public:
	CString senderID;
	CString receiverID;
	CString M_title;
	CString M_content;
	CString M_dec;
	BIGNUM *p;
	BIGNUM *g;
	BN_CTX *ctx;
	

	


	void send(User *sender, User *receiver, CString title, CString content);
	void lookup(User *sender, User * receiver);
	Message();
	~Message();
};


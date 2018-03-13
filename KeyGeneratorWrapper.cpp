//
// Created by 星落_月残 on 2017/12/21.
//

#include "KeyGeneratorWrapper.h"
#include <cryptopp/rsa.h>
#include <cryptopp/rc6.h>
#include <cryptopp/twofish.h>
#include <cryptopp/serpent.h>
#include <cryptopp/idea.h>
#include <cryptopp/salsa.h>
#include <cryptopp/chacha.h>
#include <cryptopp/panama.h>
#include <cryptopp/base64.h>


namespace CryptoppWrapper
{
	std::tuple<std::string,std::string> AESKeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)AES::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)AES::BLOCKSIZE);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}

	std::tuple<std::string,std::string> RC6KeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)RC6::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)RC6::BLOCKSIZE);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}

	std::tuple<std::string,std::string> TwoFishKeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)Twofish::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)Twofish::BLOCKSIZE);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}

	std::tuple<std::string,std::string> SerpentKeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)Serpent::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)Serpent::BLOCKSIZE);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}

	std::tuple<std::string,std::string> IDEAKeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)IDEA::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)IDEA::BLOCKSIZE);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}

	std::tuple<std::string,std::string> Salsa20KeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)Salsa20::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)Salsa20::IV_LENGTH);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}

	std::tuple<std::string,std::string> ChaCha20KeyGenerator()
	{
		SecByteBlock key(nullptr,(unsigned long long int)ChaCha20::MAX_KEYLENGTH);
		SecByteBlock iv(nullptr,(unsigned long long int)ChaCha20::IV_LENGTH);
		AutoSeededRandomPool rnd;
		rnd.GenerateBlock(key,key.size());
		rnd.GenerateBlock(iv,iv.size());

		std::string KEY(reinterpret_cast<const char *>(key.data()),key.size());
		std::string IV(reinterpret_cast<const char *>(iv.data()),iv.size());
		std::string bKEY;
		std::string bIV;
		StringSource(KEY,true,new Base64Encoder(new StringSink(bKEY)));
		StringSource(IV,true,new Base64Encoder(new StringSink(bIV)));
		auto result=std::make_tuple(bKEY,bIV);
		return result;
	}


	std::tuple<std::string,std::string,unsigned long long int> RSAKeyGenerator(unsigned int keyLength)
	{
		std::string privateKeyString,publicKeyString;

		AutoSeededRandomPool rnd;
		InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rnd,keyLength);
		RSA::PrivateKey privatekey(params);
		RSA::PublicKey publickey(params);

		RSAES_OAEP_SHA_Decryptor priv(privatekey);
		HexEncoder privString(new StringSink(privateKeyString));
		priv.GetMaterial().Save(privString);//DEREncode(privString);
		privString.MessageEnd();

		RSAES_OAEP_SHA_Encryptor publ(publickey);
		HexEncoder publString(new StringSink(publicKeyString));
		publ.GetMaterial().Save(publString);//DEREncode(publString);
		publString.MessageEnd();

		auto result=std::make_tuple(privateKeyString,publicKeyString,publ.FixedMaxPlaintextLength());
		return result;
	};
}
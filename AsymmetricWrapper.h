//
// Created by 星落_月残 on 2017/12/21.
//

#ifndef CRYPTOPPWRAPPER_ASYMMETRICWRAPPER_H
#define CRYPTOPPWRAPPER_ASYMMETRICWRAPPER_H

#include "BaseWrapper.h"
#include <cryptopp/rsa.h>


namespace CryptoppWrapper
{
	enum PublicProcessType
	{
		Encryption,Verification
	};
	enum PrivateProcessType
	{
		Decryption,Signature
	};
	template<PublicProcessType PPC=CryptoppWrapper::PublicProcessType::Encryption,SourceType SRC=CryptoppWrapper::SourceType::FromString,DestinationType DST=CryptoppWrapper::DestinationType::ToString>
	RandomPool &GlobalRNG();


	template<PublicProcessType PPC,SourceType SRC,DestinationType DST>
	class AsymmetricPublicProcess
	{
	public:
		const std::string &getPublicKey() const;
		void setPublicKey(const std::string &publicKey);
		virtual std::string operator ()(std::string input,std::string output)=0;
	protected:
		AsymmetricPublicProcess(std::string inPublicKey);
		AsymmetricPublicProcess()=delete;
		AsymmetricPublicProcess(const AsymmetricPublicProcess<PPC,SRC,DST> &another)=delete;
		AsymmetricPublicProcess(const AsymmetricPublicProcess<PPC,SRC,DST> &&another)=delete;
		//禁用默认，复制，移动构造函数
		std::string publicKey;
	};

	template<PrivateProcessType PPC,SourceType SRC,DestinationType DST>
	class AsymmetricPrivateProcess
	{
	public:
		const std::string &getPrivateKey() const;
		void setPrivateKey(const std::string &privateKey);
		virtual std::string operator ()(std::string input,std::string output)=0;
	protected:AsymmetricPrivateProcess(std::string inPrivateKey);
		AsymmetricPrivateProcess()=delete;
		AsymmetricPrivateProcess(const AsymmetricPrivateProcess<PPC,SRC,DST> &another)=delete;
		AsymmetricPrivateProcess(const AsymmetricPrivateProcess<PPC,SRC,DST> &&another)=delete;
		//禁用默认，复制，移动构造函数
		std::string privateKey;
	};

	template<PublicProcessType PPC,SourceType SRC,DestinationType DST>
	class RSAPublicProcess final: public AsymmetricPublicProcess<PPC,SRC,DST>
	{
	public:
		RSAPublicProcess(std::string inPublicKey);
		std::string operator ()(std::string input,std::string output) override;
	protected:
		RSAPublicProcess()=delete;
	};

	template<PrivateProcessType PPC,SourceType SRC,DestinationType DST>
	class RSAPrivateProcess final: public AsymmetricPrivateProcess<PPC,SRC,DST>
	{
	public:
		RSAPrivateProcess(std::string inPrivateKey);
		std::string operator ()(std::string input,std::string output) override;
	protected:
		RSAPrivateProcess()=delete;
	};

}

template<CryptoppWrapper::PublicProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
RandomPool &CryptoppWrapper::GlobalRNG()
{
	static RandomPool randomPool;
	return randomPool;
}
template<CryptoppWrapper::PublicProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::AsymmetricPublicProcess<PPC,SRC,DST>::AsymmetricPublicProcess(std::string inPublicKey)
		:publicKey(inPublicKey)
{
}
template<CryptoppWrapper::PublicProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
const std::string &CryptoppWrapper::AsymmetricPublicProcess<PPC,SRC,DST>::getPublicKey() const
{
	return publicKey;
}
template<CryptoppWrapper::PublicProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
void CryptoppWrapper::AsymmetricPublicProcess<PPC,SRC,DST>::setPublicKey(const std::string &publicKey)
{
	AsymmetricPublicProcess::publicKey=publicKey;
}
template<CryptoppWrapper::PublicProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::RSAPublicProcess<PPC,SRC,DST>::RSAPublicProcess(std::string inPublicKey)
		:AsymmetricPublicProcess<PPC,SRC,DST>(inPublicKey)
{
}
template<CryptoppWrapper::PublicProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::RSAPublicProcess<PPC,SRC,DST>::operator ()(std::string input,std::string output)
{
	if(PPC==CryptoppWrapper::PublicProcessType::Encryption)
	{
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				AutoSeededRandomPool rnd;
				RSAES_OAEP_SHA_Encryptor publ(publString);
				StringSource(input,true,new PK_EncryptorFilter(rnd,publ,new HexEncoder(new StringSink(output))));
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				AutoSeededRandomPool rnd;
				RSAES_OAEP_SHA_Encryptor publ(publString);
				FileSource(input.c_str(),true,new PK_EncryptorFilter(rnd,publ,new HexEncoder(new StringSink(output))));
			}
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				AutoSeededRandomPool rnd;
				RSAES_OAEP_SHA_Encryptor publ(publString);
				StringSource(input,true,new PK_EncryptorFilter(rnd,publ,new HexEncoder(new FileSink(output.c_str()))));
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				AutoSeededRandomPool rnd;
				RSAES_OAEP_SHA_Encryptor publ(publString);
				FileSource(input.c_str(),true,new PK_EncryptorFilter(rnd,publ,new HexEncoder(new FileSink(output.c_str()))));
			}
			else;
		else;
		return output;
	}
	else if(PPC==CryptoppWrapper::PublicProcessType::Verification)//传入参数意义修改，此处input为签名文件，output为原始文件
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				RSASS<PKCS1v15,SHA>::Verifier publ(publString);

				StringSource signatureFile(input,true,new HexDecoder);
				if(signatureFile.MaxRetrievable()!=publ.SignatureLength())
					return "0";
				SecByteBlock signature(publ.SignatureLength());
				signatureFile.Get(signature,signature.size());
				SignatureVerificationFilter *verifierFilter=new SignatureVerificationFilter(publ);
				verifierFilter->Put(signature,publ.SignatureLength());
				StringSource f(output,true,verifierFilter);
				if(verifierFilter->GetLastResult())
					return "1";
				else
					return "0";
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				RSASS<PKCS1v15,SHA>::Verifier publ(publString);

				FileSource signatureFile(input.c_str(),true,new HexDecoder);
				if(signatureFile.MaxRetrievable()!=publ.SignatureLength())
					return "0";
				SecByteBlock signature(publ.SignatureLength());
				signatureFile.Get(signature,signature.size());
				SignatureVerificationFilter *verifierFilter=new SignatureVerificationFilter(publ);
				verifierFilter->Put(signature,publ.SignatureLength());
				StringSource f(output,true,verifierFilter);
				if(verifierFilter->GetLastResult())
					return "1";
				else
					return "0";
			}
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				RSASS<PKCS1v15,SHA1>::Verifier publ(publString);

				StringSource signatureFile(input,true,new HexDecoder);
				if(signatureFile.MaxRetrievable()!=publ.SignatureLength())
					return "0";
				SecByteBlock signature(publ.SignatureLength());
				signatureFile.Get(signature,signature.size());
				SignatureVerificationFilter *verifierFilter=new SignatureVerificationFilter(publ);
				verifierFilter->Put(signature,publ.SignatureLength());
				FileSource f(output.c_str(),true,verifierFilter);
				if(verifierFilter->GetLastResult())
					return "1";
				else
					return "0";
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource publString(AsymmetricPublicProcess<PPC,SRC,DST>::publicKey,true,new HexDecoder);
				RSASS<PKCS1v15,SHA1>::Verifier publ(publString);

				FileSource signatureFile(input.c_str(),true,new HexDecoder);
				if(signatureFile.MaxRetrievable()!=publ.SignatureLength())
					return "0";
				SecByteBlock signature(publ.SignatureLength());
				signatureFile.Get(signature,signature.size());
				SignatureVerificationFilter *verifierFilter=new SignatureVerificationFilter(publ);
				verifierFilter->Put(signature,publ.SignatureLength());
				FileSource f(output.c_str(),true,verifierFilter);
				if(verifierFilter->GetLastResult())
					return "1";
				else
					return "0";
			}
			else;
		else;
	else;
	return "0";
}


template<CryptoppWrapper::PrivateProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::AsymmetricPrivateProcess<PPC,SRC,DST>::AsymmetricPrivateProcess(std::string inPrivateKey)
		:privateKey(inPrivateKey)
{
}
template<CryptoppWrapper::PrivateProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
const std::string &CryptoppWrapper::AsymmetricPrivateProcess<PPC,SRC,DST>::getPrivateKey() const
{
	return privateKey;
}
template<CryptoppWrapper::PrivateProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
void CryptoppWrapper::AsymmetricPrivateProcess<PPC,SRC,DST>::setPrivateKey(const std::string &privateKey)
{
	AsymmetricPrivateProcess::privateKey=privateKey;
}
template<CryptoppWrapper::PrivateProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::RSAPrivateProcess<PPC,SRC,DST>::RSAPrivateProcess(std::string inPrivateKey)
		:AsymmetricPrivateProcess<PPC,SRC,DST>(inPrivateKey)
{
}
template<CryptoppWrapper::PrivateProcessType PPC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::RSAPrivateProcess<PPC,SRC,DST>::operator ()(std::string input,std::string output)
{
	if(PPC==CryptoppWrapper::PrivateProcessType::Decryption)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSAES_OAEP_SHA_Decryptor priv(privString);
				StringSource(input,true,new HexDecoder(new PK_DecryptorFilter(GlobalRNG(),priv,new StringSink(output))));
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSAES_OAEP_SHA_Decryptor priv(privString);
				FileSource(input.c_str(),true,new HexDecoder(new PK_DecryptorFilter(GlobalRNG(),priv,new StringSink(output))));
			}
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSAES_OAEP_SHA_Decryptor priv(privString);
				StringSource(input,true,new HexDecoder(new PK_DecryptorFilter(GlobalRNG(),priv,new FileSink(output.c_str()))));
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSAES_OAEP_SHA_Decryptor priv(privString);
				FileSource(input.c_str(),true,new HexDecoder(new PK_DecryptorFilter(GlobalRNG(),priv,new FileSink(output.c_str()))));
			}
			else;
		else;
	else if(PPC==CryptoppWrapper::PrivateProcessType::Signature)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSASSA_PKCS1v15_SHA_Signer priv(privString);
				StringSource(input,true,new SignerFilter(GlobalRNG(),priv,new HexEncoder(new StringSink(output))));
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSASSA_PKCS1v15_SHA_Signer priv(privString);
				FileSource(input.c_str(),true,new SignerFilter(GlobalRNG(),priv,new HexEncoder(new StringSink(output))));
			}
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSASSA_PKCS1v15_SHA_Signer priv(privString);
				StringSource(input,true,new SignerFilter(GlobalRNG(),priv,new HexEncoder(new FileSink(output.c_str()))));
			}
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
			{
				StringSource privString(AsymmetricPrivateProcess<PPC,SRC,DST>::privateKey,true,new HexDecoder);
				RSASSA_PKCS1v15_SHA_Signer priv(privString);
				FileSource(input.c_str(),true,new SignerFilter(GlobalRNG(),priv,new HexEncoder(new FileSink(output.c_str()))));
			}
			else;
		else;
	return output;
}
#endif //CRYPTOPPWRAPPER_ASYMMETRICWRAPPER_H

//
// Created by 星落_月残 on 2017/12/21.
//

#ifndef CRYPTOPPWRAPPER_SYMMETRICWRAPPER_H
#define CRYPTOPPWRAPPER_SYMMETRICWRAPPER_H

#include "BaseWrapper.h"
#include <cryptopp/aes.h>
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
	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class SymmetricProcess
	{
	public:
		SymmetricProcess(const SecByteBlock &Key,const SecByteBlock &IV);
		SymmetricProcess(const std::string &Key,const std::string &IV);
		const SecByteBlock &getKey() const;
		const SecByteBlock &getIv() const;
		void setKey(const SecByteBlock &key);
		void setIv(const SecByteBlock &iv);
		void setKey(const std::string &key);
		void setIv(const std::string &iv);
		virtual std::string operator ()(std::string input,std::string output)=0;
		SymmetricProcess()=delete;
		SymmetricProcess(const SymmetricProcess<PRC,SRC,DST> &another)=delete;
		SymmetricProcess(const SymmetricProcess<PRC,SRC,DST> &&another)=delete;
		//禁用默认，复制，移动构造函数
	protected:
		SecByteBlock key;
		SecByteBlock iv;
	};

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class AES_CFBProcess final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		AES_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV);
		AES_CFBProcess(const std::string &Key,const std::string &IV);
		std::string operator ()(std::string input,std::string output) override;
		AES_CFBProcess()=delete;
	};

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class RC6_CFBProcess final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		RC6_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV);
		RC6_CFBProcess(const std::string &Key,const std::string &IV);
		std::string operator ()(std::string input,std::string output) override;
		RC6_CFBProcess()=delete;
	};

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class TwoFish_CFBProcess final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		TwoFish_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV);
		TwoFish_CFBProcess(const std::string &Key,const std::string &IV);
		std::string operator ()(std::string input,std::string output) override;
		TwoFish_CFBProcess()=delete;
	};

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class Serpent_CFBProcess final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		Serpent_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV);
		Serpent_CFBProcess(const std::string &Key,const std::string &IV);
		std::string operator ()(std::string input,std::string output) override;
		Serpent_CFBProcess()=delete;
	};

/*	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class IDEA_CFBProcess final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		IDEA_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV);
		IDEA_CFBProcess(const std::string &Key,const SecByteBlock &IV);
		std::string operator ()(std::string input,std::string output) override;
		IDEA_CFBProcess()=delete;
	};*/

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class Salsa20Process final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		Salsa20Process(const SecByteBlock &Key,const SecByteBlock &IV);
		Salsa20Process(const std::string &Key,const std::string &IV);
		std::string operator ()(std::string input,std::string output) override;
		Salsa20Process()=delete;
	};

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class ChaCha20Process final: public SymmetricProcess<PRC,SRC,DST>
	{
	public:
		ChaCha20Process(const SecByteBlock &Key,const SecByteBlock &IV);
		ChaCha20Process(const std::string &Key,const std::string &IV);
		std::string operator ()(std::string input,std::string output) override;
		ChaCha20Process()=delete;
	};

}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::SymmetricProcess(const SecByteBlock &Key,const SecByteBlock &IV)
		:key(Key),iv(IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::SymmetricProcess(const std::string &Key,const std::string &IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	SymmetricProcess::key=tKey;
	SymmetricProcess::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
const SecByteBlock &CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::getKey() const
{
	return key;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
const SecByteBlock &CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::getIv() const
{
	return iv;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
void CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::setKey(const SecByteBlock &key)
{
	SymmetricProcess::key=key;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
void CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::setIv(const SecByteBlock &iv)
{
	SymmetricProcess::iv=iv;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
void CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::setKey(const std::string &key)
{
	SecByteBlock tKey(reinterpret_cast<const byte *>(key.data()),key.size());
	SymmetricProcess::key=tKey;

}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
void CryptoppWrapper::SymmetricProcess<PRC,SRC,DST>::setIv(const std::string &iv)
{
	SecByteBlock tIV(reinterpret_cast<const byte *>(iv.data()),iv.size());
	SymmetricProcess::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::AES_CFBProcess<PRC,SRC,DST>::AES_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::AES_CFBProcess<PRC,SRC,DST>::AES_CFBProcess(const std::string &Key,const std::string &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	AES_CFBProcess::key=tKey;
	AES_CFBProcess::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::AES_CFBProcess<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	CFB_Mode<AES>::Encryption AES_CFBEncrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	CFB_Mode<AES>::Decryption AES_CFBDecrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(AES_CFBEncrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(AES_CFBEncrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(AES_CFBEncrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(AES_CFBEncrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(AES_CFBDecrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(AES_CFBDecrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(AES_CFBDecrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(AES_CFBDecrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}

template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::RC6_CFBProcess<PRC,SRC,DST>::RC6_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::RC6_CFBProcess<PRC,SRC,DST>::RC6_CFBProcess(const std::string &Key,const std::string &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	RC6_CFBProcess::key=tKey;
	RC6_CFBProcess::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::RC6_CFBProcess<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	CFB_Mode<RC6>::Encryption RC6_CFBEncrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	CFB_Mode<RC6>::Decryption RC6_CFBDecrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(RC6_CFBEncrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(RC6_CFBEncrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(RC6_CFBEncrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(RC6_CFBEncrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(RC6_CFBDecrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(RC6_CFBDecrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(RC6_CFBDecrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(RC6_CFBDecrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}


template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::TwoFish_CFBProcess<PRC,SRC,DST>::TwoFish_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::TwoFish_CFBProcess<PRC,SRC,DST>::TwoFish_CFBProcess(const std::string &Key,const std::string &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	TwoFish_CFBProcess::key=tKey;
	TwoFish_CFBProcess::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::TwoFish_CFBProcess<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	CFB_Mode<Twofish>::Encryption TwoFish_CFBEncrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	CFB_Mode<Twofish>::Decryption TwoFish_CFBDecrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(TwoFish_CFBEncrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(TwoFish_CFBEncrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(TwoFish_CFBEncrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(TwoFish_CFBEncrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}

template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::Serpent_CFBProcess<PRC,SRC,DST>::Serpent_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::Serpent_CFBProcess<PRC,SRC,DST>::Serpent_CFBProcess(const std::string &Key,const std::string &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	Serpent_CFBProcess::key=tKey;
	Serpent_CFBProcess::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::Serpent_CFBProcess<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	CFB_Mode<Serpent>::Encryption Serpent_CFBEncrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	CFB_Mode<Serpent>::Decryption Serpent_CFBDecrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Serpent_CFBEncrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Serpent_CFBEncrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Serpent_CFBEncrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Serpent_CFBEncrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Serpent_CFBDecrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Serpent_CFBDecrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Serpent_CFBDecrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Serpent_CFBDecrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}

/*
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::IDEA_CFBProcess<PRC,SRC,DST>::IDEA_CFBProcess(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}

template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::IDEA_CFBProcess<PRC,SRC,DST>::IDEA_CFBProcess(const std::string &Key,const SecByteBlock &IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	IDEA_CFBProcess::key=tKey;
	IDEA_CFBProcess::iv=tIV;
}

template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::IDEA_CFBProcess<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	CFB_Mode<IDEA>::Encryption IDEA_CFBEncrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	CFB_Mode<IDEA>::Decryption IDEA_CFBDecrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(IDEA_CFBEncrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(IDEA_CFBEncrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(IDEA_CFBEncrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(IDEA_CFBEncrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(IDEA_CFBDecrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(IDEA_CFBDecrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(IDEA_CFBDecrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(IDEA_CFBDecrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}
*/

template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::Salsa20Process<PRC,SRC,DST>::Salsa20Process(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::Salsa20Process<PRC,SRC,DST>::Salsa20Process(const std::string &Key,const std::string &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	Salsa20Process::key=tKey;
	Salsa20Process::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::Salsa20Process<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	Salsa20::Encryption Salsa20Encrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	Salsa20::Decryption Salsa20Decrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Salsa20Encrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Salsa20Encrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Salsa20Encrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Salsa20Encrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Salsa20Decrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Salsa20Decrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(Salsa20Decrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(Salsa20Decrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}


template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::ChaCha20Process<PRC,SRC,DST>::ChaCha20Process(const SecByteBlock &Key,const SecByteBlock &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
CryptoppWrapper::ChaCha20Process<PRC,SRC,DST>::ChaCha20Process(const std::string &Key,const std::string &IV)
		:SymmetricProcess<PRC,SRC,DST>(Key,IV)
{
	std::string bKey,bIV;
	StringSource(Key,true,new Base64Decoder(new StringSink(bKey)));
	StringSource(IV,true,new Base64Decoder(new StringSink(bIV)));
	SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
	SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
	ChaCha20Process::key=tKey;
	ChaCha20Process::iv=tIV;
}
template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::ChaCha20Process<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	ChaCha20::Encryption ChaCha20Encrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	ChaCha20::Decryption ChaCha20Decrypt(SymmetricProcess<PRC,SRC,DST>::key,SymmetricProcess<PRC,SRC,DST>::key.size(),SymmetricProcess<PRC,SRC,DST>::iv);
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(ChaCha20Encrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(ChaCha20Encrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(ChaCha20Encrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(ChaCha20Encrypt,new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(ChaCha20Decrypt,new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(ChaCha20Decrypt,new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new StreamTransformationFilter(ChaCha20Decrypt,new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new StreamTransformationFilter(ChaCha20Decrypt,new FileSink(output.c_str())));
			else;
		else;
	return output;
}


#endif //CRYPTOPPWRAPPER_SYMMETRICWRAPPER_H

//
// Created by 星落_月残 on 2017/12/21.
//

#ifndef CRYPTOPPWRAPPER_HASHWRAPPER_H
#define CRYPTOPPWRAPPER_HASHWRAPPER_H

#include "BaseWrapper.h"
#include <cryptopp/sha3.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/base64.h>


namespace CryptoppWrapper
{
	template<SourceType SRC,DestinationType DST>
	class HashProcess
	{
	public:
		virtual std::string operator ()(std::string input,std::string output)=0;
	protected:
		HashProcess(){};
	};

	template<ProcessType PRC,SourceType SRC,DestinationType DST>
	class Base64Process final: public HashProcess<SRC,DST>
	{
	public:
		Base64Process(){};
		std::string operator ()(std::string input,std::string output) override;
	};

	template<SourceType SRC,DestinationType DST>
	class SHA3_512HashProcess final: public HashProcess<SRC,DST>
	{
	public:
		SHA3_512HashProcess(){};
		std::string operator ()(std::string input,std::string output) override;
	};

	template<SourceType SRC,DestinationType DST>
	class WhirlpoolHashProcess final: public HashProcess<SRC,DST>
	{
	public:
		WhirlpoolHashProcess(){};
		std::string operator ()(std::string input,std::string output) override;
	};
}

template<CryptoppWrapper::ProcessType PRC,CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::Base64Process<PRC,SRC,DST>::operator ()(std::string input,std::string output)
{
	if(PRC==CryptoppWrapper::ProcessType::Encrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new Base64Encoder(new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new Base64Encoder(new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new Base64Encoder(new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new Base64Encoder(new FileSink(output.c_str())));
			else;
		else;
	else if(PRC==CryptoppWrapper::ProcessType::Decrypt)
		if(DST==CryptoppWrapper::DestinationType::ToString)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new Base64Decoder(new StringSink(output)));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new Base64Decoder(new StringSink(output)));
			else;
		else if(DST==CryptoppWrapper::DestinationType::ToFile)
			if(SRC==CryptoppWrapper::SourceType::FromString)
				StringSource(input,true,new Base64Decoder(new FileSink(output.c_str())));
			else if(SRC==CryptoppWrapper::SourceType::FromFile)
				FileSource(input.c_str(),true,new Base64Decoder(new FileSink(output.c_str())));
			else;
		else;
	return output;
}

template<CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::SHA3_512HashProcess<SRC,DST>::operator ()(std::string input,std::string output)
{
	SHA3_512 SHA512Generator;
	if(DST==CryptoppWrapper::DestinationType::ToString)
		if(SRC==CryptoppWrapper::SourceType::FromString)
			StringSource(input,true,new HashFilter(SHA512Generator,new HexEncoder(new StringSink(output))));
		else if(SRC==CryptoppWrapper::SourceType::FromFile)
			FileSource(input.c_str(),true,new HashFilter(SHA512Generator,new HexEncoder(new StringSink(output))));
		else;
	else if(DST==CryptoppWrapper::DestinationType::ToFile)
		if(SRC==CryptoppWrapper::SourceType::FromString)
			StringSource(input,true,new HashFilter(SHA512Generator,new HexEncoder(new FileSink(output.c_str()))));
		else if(SRC==CryptoppWrapper::SourceType::FromFile)
			FileSource(input.c_str(),true,new HashFilter(SHA512Generator,new HexEncoder(new FileSink(output.c_str()))));
		else;
	return output;
}

template<CryptoppWrapper::SourceType SRC,CryptoppWrapper::DestinationType DST>
std::string CryptoppWrapper::WhirlpoolHashProcess<SRC,DST>::operator ()(std::string input,std::string output)
{
	Whirlpool WhirlpoolGenerator;
	if(DST==CryptoppWrapper::DestinationType::ToString)
		if(SRC==CryptoppWrapper::SourceType::FromString)
			StringSource(input,true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new StringSink(output))));
		else if(SRC==CryptoppWrapper::SourceType::FromFile)
			FileSource(input.c_str(),true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new StringSink(output))));
		else;
	else if(DST==CryptoppWrapper::DestinationType::ToFile)
		if(SRC==CryptoppWrapper::SourceType::FromString)
			StringSource(input,true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new FileSink(output.c_str()))));
		else if(SRC==CryptoppWrapper::SourceType::FromFile)
			FileSource(input.c_str(),true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new FileSink(output.c_str()))));
		else;
	return output;
}

#endif //CRYPTOPPWRAPPER_HASHWRAPPER_H

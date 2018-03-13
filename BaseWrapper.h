//
// Created by 星落_月残 on 2017/12/21.
//

#ifndef CRYPTOPPWRAPPER_BASEWRAPPER_H
#define CRYPTOPPWRAPPER_BASEWRAPPER_H
//std
#include <iostream>
#include <fstream>
#include <memory>
#include <tuple>
#include <random>
#include <sstream>
//Basic
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/randpool.h>
#include <cryptopp/osrng.h>



using namespace CryptoPP;

namespace CryptoppWrapper
{
	enum ProcessType
	{
		Encrypt,Decrypt
	};
	enum SourceType
	{
		FromString,FromFile
	};
	enum DestinationType
	{
		ToString,ToFile
	};

}
#endif //CRYPTOPPWRAPPER_BASEWRAPPER_H

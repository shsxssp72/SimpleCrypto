//
// Created by 星落_月残 on 2017/12/21.
//

#ifndef CRYPTOPPWRAPPER_KEYGENERATORWRAPPER_H
#define CRYPTOPPWRAPPER_KEYGENERATORWRAPPER_H

#include "BaseWrapper.h"

namespace CryptoppWrapper
{
//Block
	std::tuple<std::string,std::string> AESKeyGenerator();
	std::tuple<std::string,std::string> RC6KeyGenerator();
	std::tuple<std::string,std::string> TwoFishKeyGenerator();
	std::tuple<std::string,std::string> SerpentKeyGenerator();
	std::tuple<std::string,std::string> IDEAKeyGenerator();

//Stream
	std::tuple<std::string,std::string> Salsa20KeyGenerator();
	std::tuple<std::string,std::string> ChaCha20KeyGenerator();

//Asymmetric
	std::tuple<std::string,std::string,unsigned long long int> RSAKeyGenerator(unsigned int keyLength);
}
#endif //CRYPTOPPWRAPPER_KEYGENERATORWRAPPER_H

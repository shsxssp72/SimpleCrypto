#include <iostream>
#include <cstring>
#include <tuple>
#include <exception>
#include <cryptopp/sha3.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/base64.h>
#include <cryptopp/rc6.h>
#include <cryptopp/twofish.h>
#include <cryptopp/serpent.h>
#include <cryptopp/salsa.h>
#include <cryptopp/chacha.h>
#include "KeyGeneratorWrapper.h"


namespace SimpleCrypto
{
	enum Algorithm
	{
		Base64,SHA3_512,Whirlpool,AES,RC6,TwoFish,Serpent,Salsa20,ChaCha20,/*RSA,*/Null
	};

	struct Instruction
	{
		Algorithm alg=Null;
		bool type=true;//!true-encode,false-decode
		bool inputType=true;//!true-string,false-file
		bool outputType=true;//!true-string,false-file
		bool isKeyGenerator=false;
		bool isHelp=false;
		//! input and output passed separately,not here.
		Instruction()=default;
		Instruction(Algorithm alg,bool type,bool inputType,bool outputType)
				:alg(alg),type(type),inputType(inputType),outputType(outputType)
		{}
	};
}
class SimpleCryptoException: public std::exception
{
public:
	explicit SimpleCryptoException(const std::string &message)
			:message(message)
	{
	}
	const char *what() noexcept
	{
		std::cerr<<message<<std::endl;
		return message.c_str();
	}
	const std::string &getMessage() const
	{
		return message;
	}

	~SimpleCryptoException() noexcept override=default;
private:
	const std::string message;
};

std::tuple<SimpleCrypto::Instruction,std::string,std::string,std::string,std::string> getInstruction(int argc,char *argv[]);
std::string getAnswer(const SimpleCrypto::Instruction &instruction,std::string &input,std::string &output,const std::string &key,const std::string &iv);
std::tuple<std::string,std::string> getKey(const SimpleCrypto::Instruction &instruction);
void Introduction();


int main(int argc,char *argv[])
{
	auto parserResult=getInstruction(argc,argv);
	auto instruct=std::get<0>(parserResult);
	if(instruct.isHelp)
		Introduction();
	else if(instruct.isKeyGenerator)
	{
		auto KeyAndIV=getKey(std::get<0>(parserResult));
		std::string key=std::get<0>(KeyAndIV);
		std::string iv=std::get<1>(KeyAndIV);
		if(!instruct.outputType)
		{
			std::string output=std::get<2>(parserResult);
			std::ofstream fout(output);
			fout<<key<<std::endl<<iv<<std::endl;
			std::cout<<"Saved to "<<output<<std::endl;
		}
		else
			std::cout<<"key: "<<key<<std::endl<<"iv: "<<iv<<std::endl;
	}
	else
	{
		std::string answer=getAnswer(instruct,std::get<1>(parserResult),std::get<2>(parserResult),std::get<3>(parserResult),std::get<4>(parserResult));
		std::cout<<answer<<std::endl;
	}
	return 0;
}


std::tuple<SimpleCrypto::Instruction,std::string,std::string,std::string,std::string> getInstruction(int argc,char **argv) try
{
	auto result=SimpleCrypto::Instruction();
	std::string input,output,key,iv;
	if(argc<=1)
		throw SimpleCryptoException("Invalid option");
	for(int i=1;i<argc;++i)
	{

		if(argv[i][0]=='-')//parameter
		{
			size_t length=strlen(argv[i]);
			if(length!=2)
				throw SimpleCryptoException("Invalid option");
			/*{
				std::cerr<<"Invalid option"<<std::endl;
				return std::make_tuple<SimpleCrypto::Instruction,std::string,std::string>(SimpleCrypto::Instruction(),"","");
			}*/
			switch(argv[i][1])
			{
				case 'a':
					if(i>=argc-1)
						throw SimpleCryptoException("Invalid option");
					if(!strcmp(argv[i+1],"base64"))
						result.alg=SimpleCrypto::Base64;
					else if(!strcmp(argv[i+1],"sha3-512"))
						result.alg=SimpleCrypto::SHA3_512;
					else if(!strcmp(argv[i+1],"whirlpool"))
						result.alg=SimpleCrypto::Whirlpool;
					else if(!strcmp(argv[i+1],"aes"))
						result.alg=SimpleCrypto::AES;
					else if(!strcmp(argv[i+1],"rc6"))
						result.alg=SimpleCrypto::RC6;
					else if(!strcmp(argv[i+1],"twofish"))
						result.alg=SimpleCrypto::TwoFish;
					else if(!strcmp(argv[i+1],"serpent"))
						result.alg=SimpleCrypto::Serpent;
					else if(!strcmp(argv[i+1],"salsa20"))
						result.alg=SimpleCrypto::Salsa20;
					else if(!strcmp(argv[i+1],"chacha20"))
						result.alg=SimpleCrypto::ChaCha20;
//					else if(!strcmp(argv[i+1],"rsa"))
//						result.alg=SimpleCrypto::RSA;
					i++;
					break;
				case 'm':
					if(i>=argc-1)
						throw SimpleCryptoException("Invalid option");
					if(!strcmp(argv[i+1],"encode"))
						result.type=true;
					else if(!strcmp(argv[i+1],"decode"))
						result.type=false;
					i++;
					break;
				case 'i':
					if(i>=argc-2)
						throw SimpleCryptoException("Invalid option");
					if(!strcmp(argv[i+1],"string"))
						result.inputType=true;
					else if(!strcmp(argv[i+1],"file"))
						result.inputType=false;
					input=argv[i+2];
					break;
				case 'o':
					if(i>=argc-1)
						throw SimpleCryptoException("Invalid option");
					if(!strcmp(argv[i+1],"string"))
					{
						result.outputType=true;
						output="";
					}
					else if(!strcmp(argv[i+1],"file"))
					{
						if(i>=argc-2)
							throw SimpleCryptoException("Invalid option");
						result.outputType=false;
						output=argv[i+2];
					}
					break;
				case 'g':
					result.isKeyGenerator=true;
					break;
				case 'k':
					if(i>=argc-1)
						throw SimpleCryptoException("Invalid option");
					if(!strcmp(argv[i+1],"string"))
						if(i>=argc-3)
							throw SimpleCryptoException("Invalid option");
						else
						{
							key=argv[i+2];
							iv=argv[i+3];
						}
					else if(!strcmp(argv[i+1],"file"))
						if(i>=argc-2)
							throw SimpleCryptoException("Invalid option");
						else
						{
							std::ifstream fin(argv[i+2]);
							if(!fin.is_open())
								throw SimpleCryptoException("Cannot open file.");
							fin>>key>>iv;
							fin.close();
						}
					break;
				case 'h':
					result.isHelp=true;
					break;
				default:
					throw SimpleCryptoException("Invalid option");
			}
		}
	}
	return std::make_tuple(result,input,output,key,iv);
}
catch(SimpleCryptoException &error)
{
	std::cerr<<error.getMessage()<<std::endl;
}

std::tuple<std::string,std::string> getKey(const SimpleCrypto::Instruction &instruction) try
{
	using namespace CryptoppWrapper;
	switch(instruction.alg)
	{
		case SimpleCrypto::Algorithm::Base64:
			throw SimpleCryptoException("Invalid Algorithm");
		case SimpleCrypto::Algorithm::SHA3_512:
			throw SimpleCryptoException("Invalid Algorithm");
		case SimpleCrypto::Algorithm::Whirlpool:
			throw SimpleCryptoException("Invalid Algorithm");
		case SimpleCrypto::Algorithm::AES:
			return AESKeyGenerator();
		case SimpleCrypto::Algorithm::RC6:
			return RC6KeyGenerator();
		case SimpleCrypto::Algorithm::TwoFish:
			return TwoFishKeyGenerator();
		case SimpleCrypto::Algorithm::Serpent:
			return SerpentKeyGenerator();
		case SimpleCrypto::Algorithm::Salsa20:
			return Salsa20KeyGenerator();
		case SimpleCrypto::Algorithm::ChaCha20:
			return ChaCha20KeyGenerator();
		default:
			break;
	}
	return std::make_tuple("","");
}
catch(SimpleCryptoException &error)
{
	std::cerr<<error.getMessage()<<std::endl;
}

std::string getAnswer(const SimpleCrypto::Instruction &instruction,std::string &input,std::string &output,const std::string &key,const std::string &iv) try
{
	using namespace CryptoppWrapper;
	//using namespace SimpleCrypto;
	std::string result;
	switch(instruction.alg)
	{
		case SimpleCrypto::Algorithm::Base64:
		{
			if(instruction.type)
			{
				if(instruction.inputType)
				{
					if(instruction.outputType)
						StringSource(input,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(input,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					if(instruction.outputType)
						FileSource(input.c_str(),true,new Base64Encoder(new StringSink(output)));
					else
						FileSource(input.c_str(),true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{

				if(instruction.inputType)
				{
					if(instruction.outputType)
						StringSource(input,true,new Base64Decoder(new StringSink(output)));
					else
						StringSource(input,true,new Base64Decoder(new FileSink(output.c_str())));
				}
				else
				{
					if(instruction.outputType)
						FileSource(input.c_str(),true,new Base64Decoder(new StringSink(output)));
					else
						FileSource(input.c_str(),true,new Base64Decoder(new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::SHA3_512:
		{
			SHA3_512 SHA512Generator;
			if(instruction.type)
			{
				if(instruction.inputType)
				{
					if(instruction.outputType)
						StringSource(input,true,new HashFilter(SHA512Generator,new HexEncoder(new StringSink(output))));
					else
						StringSource(input,true,new HashFilter(SHA512Generator,new HexEncoder(new FileSink(output.c_str()))));
				}
				else
				{
					if(instruction.outputType)
						FileSource(input.c_str(),true,new HashFilter(SHA512Generator,new HexEncoder(new StringSink(output))));
					else
						FileSource(input.c_str(),true,new HashFilter(SHA512Generator,new HexEncoder(new FileSink(output.c_str()))));
				}
			}
			else
			{
				throw SimpleCryptoException("One-way Function");
			}
			result=output;
			break;

		}
		case SimpleCrypto::Algorithm::Whirlpool:
		{
			Whirlpool WhirlpoolGenerator;
			if(instruction.type)
			{
				if(instruction.inputType)
				{
					if(instruction.outputType)
						StringSource(input,true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new StringSink(output))));
					else
						StringSource(input,true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new FileSink(output.c_str()))));
				}
				else
				{
					if(instruction.outputType)
						FileSource(input.c_str(),true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new StringSink(output))));
					else
						FileSource(input.c_str(),true,new HashFilter(WhirlpoolGenerator,new HexEncoder(new FileSink(output.c_str()))));
				}
			}
			else
			{
				throw SimpleCryptoException("One-way Function");
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::AES:
		{
			std::string bKey,bIV;
			StringSource(key,true,new Base64Decoder(new StringSink(bKey)));
			StringSource(iv,true,new Base64Decoder(new StringSink(bIV)));
			SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
			SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
			CFB_Mode<AES>::Encryption AES_CFBEncrypt(tKey,tKey.size(),tIV);
			CFB_Mode<AES>::Decryption AES_CFBDecrypt(tKey,tKey.size(),tIV);

			if(instruction.type)
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new StreamTransformationFilter(AES_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new StreamTransformationFilter(AES_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(AES_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(AES_CFBDecrypt,new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(AES_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(AES_CFBDecrypt,new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::RC6:
		{
			std::string bKey,bIV;
			StringSource(key,true,new Base64Decoder(new StringSink(bKey)));
			StringSource(iv,true,new Base64Decoder(new StringSink(bIV)));
			SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
			SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
			CFB_Mode<RC6>::Encryption RC6_CFBEncrypt(tKey,tKey.size(),tIV);
			CFB_Mode<RC6>::Decryption RC6_CFBDecrypt(tKey,tKey.size(),tIV);

			if(instruction.type)
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new StreamTransformationFilter(RC6_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new StreamTransformationFilter(RC6_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(RC6_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(RC6_CFBDecrypt,new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(RC6_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(RC6_CFBDecrypt,new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::TwoFish:
		{
			std::string bKey,bIV;
			StringSource(key,true,new Base64Decoder(new StringSink(bKey)));
			StringSource(iv,true,new Base64Decoder(new StringSink(bIV)));
			SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
			SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
			CFB_Mode<Twofish>::Encryption TwoFish_CFBEncrypt(tKey,tKey.size(),tIV);
			CFB_Mode<Twofish>::Decryption TwoFish_CFBDecrypt(tKey,tKey.size(),tIV);

			if(instruction.type)
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new StreamTransformationFilter(TwoFish_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new StreamTransformationFilter(TwoFish_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(TwoFish_CFBDecrypt,new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::Serpent:
		{
			std::string bKey,bIV;
			StringSource(key,true,new Base64Decoder(new StringSink(bKey)));
			StringSource(iv,true,new Base64Decoder(new StringSink(bIV)));
			SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
			SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
			CFB_Mode<Serpent>::Encryption Serpent_CFBEncrypt(tKey,tKey.size(),tIV);
			CFB_Mode<Serpent>::Decryption Serpent_CFBDecrypt(tKey,tKey.size(),tIV);

			if(instruction.type)
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new StreamTransformationFilter(Serpent_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new StreamTransformationFilter(Serpent_CFBEncrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(Serpent_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(Serpent_CFBDecrypt,new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(Serpent_CFBDecrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(Serpent_CFBDecrypt,new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::Salsa20:
		{
			std::string bKey,bIV;
			StringSource(key,true,new Base64Decoder(new StringSink(bKey)));
			StringSource(iv,true,new Base64Decoder(new StringSink(bIV)));
			SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
			SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
			Salsa20::Encryption Salsa20Encrypt(tKey,tKey.size(),tIV);
			Salsa20::Decryption Salsa20Decrypt(tKey,tKey.size(),tIV);

			if(instruction.type)
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new StreamTransformationFilter(Salsa20Encrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new StreamTransformationFilter(Salsa20Encrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(Salsa20Decrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(Salsa20Decrypt,new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(Salsa20Decrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(Salsa20Decrypt,new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		case SimpleCrypto::Algorithm::ChaCha20:
		{
			std::string bKey,bIV;
			StringSource(key,true,new Base64Decoder(new StringSink(bKey)));
			StringSource(iv,true,new Base64Decoder(new StringSink(bIV)));
			SecByteBlock tKey(reinterpret_cast<const byte *>(bKey.data()),bKey.size());
			SecByteBlock tIV(reinterpret_cast<const byte *>(bIV.data()),bIV.size());
			ChaCha20::Encryption ChaCha20Encrypt(tKey,tKey.size(),tIV);
			ChaCha20::Decryption ChaCha20Decrypt(tKey,tKey.size(),tIV);

			if(instruction.type)
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new StreamTransformationFilter(ChaCha20Encrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new StreamTransformationFilter(ChaCha20Encrypt,new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new Base64Encoder(new StringSink(output)));
					else
						StringSource(tmpOutput,true,new Base64Encoder(new FileSink(output.c_str())));
				}
			}
			else
			{
				if(instruction.inputType)
				{
					std::string tmpOutput;
					StringSource(input,true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(ChaCha20Decrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(ChaCha20Decrypt,new FileSink(output.c_str())));
				}
				else
				{
					std::string tmpOutput;
					FileSource(input.c_str(),true,new Base64Decoder(new StringSink(tmpOutput)));
					if(instruction.outputType)
						StringSource(tmpOutput,true,new StreamTransformationFilter(ChaCha20Decrypt,new StringSink(output)));
					else
						StringSource(tmpOutput,true,new StreamTransformationFilter(ChaCha20Decrypt,new FileSink(output.c_str())));
				}
			}
			result=output;
			break;
		}
		default:
			break;
	}
	return result;
}
catch(SimpleCryptoException &error)
{
	std::cerr<<error.getMessage()<<std::endl;
}

void Introduction()
{
	using namespace std;
	cout<<"Simple Crypto Wrapper"<<endl<<"----Based on libcryptopp"<<endl<<endl;
	cout<<"Usage: "<<endl<<"SimpleCrypto -[a/g/h/i/k/m/o] <parameter>"<<endl<<endl;
	cout<<"		-a <algorithm_name>: Choose algorithm, cannot be omitted."<<endl;
	cout<<"			Supported: base64,sha3-512,whirlpool,aes,rc6,twofish,serpent,salsa20,chacha20"<<endl;
	cout<<"		-g: Generate keys"<<endl;
	cout<<"		-h: Print this introduction"<<endl;
	cout<<"		-i [string(default)/file] <string/filePath>: Specify input method"<<endl;
	cout<<"		-k [string(default)/file] <string/filePath>: Specify key"<<endl;
	cout<<"		-m [encode(default)/decode]: Specify process type"<<endl;
	cout<<"		-o [string(default)/file] <string/filePath>: Specify output method"<<endl<<endl;
	cout<<"Notice: "<<endl<<"The output of symmetric algorithm is encoded by Base64"<<endl;
}

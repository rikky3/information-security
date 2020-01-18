/*RSA implementation using Botan API

Install Botan: https://botan.randombit.net/
https://botan.randombit.net/handbook/building.html

Steps (for Ubuntu with g++):
1. Set LD_LIBRARY_PATH to /usr/local/lib (or wherever the libbotan files (libbotan-2.a, libbotan-2.so, libbotan-2.so.12, libbotan-2.so.12.12.1 on my system) are):

	username@pcname:~$ echo $LD_LIBRARY_PATH	//DO THESE!!!!
	/usr/local/include/botan-2/botan	(might be blank)
	username@pcname:~$ LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/
	username@pcname:~$ export LD_LIBRARY_PATH

2. Compile by passing where your headers are installed to the -I flag (in my case, they were at /usr/local/include/botan-2) and the -lbotan flag (-lbotan-2 for versions 2.0.0 and above).

3. Run by passing your PKCS #8 private key's filename (with path) at the command line.

Generating a PKCS #8 private key using OpenSSL:

	username@pcname:~$ openssl genpkey -algorithm RSA \
	>-pkeyopt rsa_keygen_bits:2048 \
	>-pkeyopt rsa_keygen_pubexp:65537 | \
	>openssl pkcs8 -topk8 -nocrypt -outform der > samp.p8
*/
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <iostream>
#include <botan/pubkey.h>
#include <botan/hex.h>

std::string hex2text(std::string hptd)
{
    std::string ptd;
	int i;
    const char* lut = "0123456789ABCDEF";	//a lookup table
	
    ptd.reserve(hptd.size() / 2);
    
    for (i = 0; i < hptd.size(); i += 2)
		ptd.push_back(((std::lower_bound(lut, lut + 16, hptd[i]) - lut) << 4) | (std::lower_bound(lut, lut + 16, hptd[i + 1]) - lut));
    
    return ptd;
}

int main(int argc, char* argv[])
{
	std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
	char c;
	
	std::unique_ptr<Botan::Private_Key> kp(Botan::PKCS8::load_key(argv[1], *rng)); 	//load keypair
	
	if(!kp->check_key(*rng, false))	//use true for strong for “strong” checking, which involves expensive operations like primality checking
		throw std::invalid_argument("Passed key is invalid");
    
	std::cout<<"Enter e to encrypt or d to decrypt: ";
	std::cin>>c;
	
	switch (c)
	{
		case 'e':
			{
				Botan::PK_Encryptor_EME encr(*kp, *rng, "EME1(SHA-256)");	//"EME1(SHA-1)" can also be used for eme
				std::string pte;
		   		Botan::PK_Signer sp(*kp, *rng, "EMSA4(SHA-256)");
					
				std::cout<<std::endl<<"Enter the plaintext not exceeding "<<encr.maximum_input_size()<<" bytes: ";
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				std::getline(std::cin, pte);
				
				std::vector<uint8_t> ptv(pte.data(), pte.data() + pte.length());

			   	std::cout<<std::endl<<"The ciphertext is: "<<std::endl<<Botan::hex_encode(encr.encrypt(ptv, *rng))<<std::endl;
		   		
		   		sp.update(ptv);
            	
				std::cout<<std::endl<<"The message signature is: "<<std::endl<<Botan::hex_encode(sp.signature(*rng))<<std::endl;
			}
			break;
		case 'd':
			{
				std::string dsign1, ct, hptd, ptd;
				Botan::PK_Decryptor_EME decr(*kp, *rng, "EME1(SHA-256)");
				Botan::PK_Verifier ver(*kp, "EMSA4(SHA-256)");
				
				std::cout<<std::endl<<"Enter the signature: ";				
				std::cin>>dsign1;
				
				std::cout<<std::endl<<"Enter the ciphertext: ";
				std::cin>>ct;
				
				hptd = Botan::hex_encode(decr.decrypt(Botan::hex_decode(ct))); 	//hptd is the hex-encoded plaintext
				ptd = hex2text(hptd);
				
				std::vector<uint8_t> ptdv(ptd.data(), ptd.data() + ptd.length());
				
				ver.update(ptdv);
				
				if(ver.check_signature(Botan::hex_decode(dsign1)))
					std::cout<<std::endl<<"The signature is valid."<<std::endl<<std::endl<<"The plaintext is: "<<ptd<<std::endl;
				else
					std::cout<<std::endl<<"The signature is invalid."<<std::endl;
			}			
			break;
		default:
			std::cout<<std::endl<<"Invalid choice entered!"<<std::endl;
	}   		
	return 0;
}

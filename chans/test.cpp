#include <gpgme.h>
#include <iostream>
#include <iomanip>
#include <vector>
int main() {
	gpgme_ctx_t Context;
	gpgme_error_t Error;
	gpgme_check_version(NULL);
	Error = gpgme_new(&Context);
	// std::cout << gpgme_strerror(Error) << std::endl;
	if (Error) return 1;
	const char* Engine = gpgme_get_dirinfo("gpg-name");
	const char* HomeDir = gpgme_get_dirinfo("homedir");
	Error = gpgme_ctx_set_engine_info(Context, GPGME_PROTOCOL_OPENPGP, Engine, HomeDir);
	// std::cout << gpgme_strerror(Error) << std::endl;
	if (Error) return 2;
	gpgme_data_t Keydata;
	Error = gpgme_data_new(&Keydata);
	// std::cout << gpgme_strerror(Error) << std::endl;
	if (Error) return 3;
	gpgme_key_t KeyObject;
	Error = gpgme_get_key(Context, "4A4F1879F61BAE15699464DA0DF20F891BC61329", &KeyObject, 0);
	gpgme_data_set_encoding (Keydata, GPGME_DATA_ENCODING_ARMOR);
	// std::cout << gpgme_strerror(Error) << std::endl;
	if (Error) return 4;
	gpgme_key_t Keys[2] = { KeyObject, NULL };
	Error = gpgme_op_export_keys(Context, Keys, 0, Keydata);
	// std::cout << gpgme_strerror(Error) << std::endl;
	if (Error) return 5;
	std::cout << gpgme_data_release_and_get_mem(Keydata, 0);
	gpgme_key_release(KeyObject);
	gpgme_release(Context);
	return 0;
}

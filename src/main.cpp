#define BOOST_LOG_DYN_LINK 1

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include <boost/log/trivial.hpp>
#include <boost/throw_exception.hpp>
#include <cstdlib>
#include <curl/curl.h>
#include <fmt/core.h>
#include <gpgme.h>
#include <iostream>
#include <map>
#include "root_certificates.hpp" // test
#include <sstream>
#include <stdexcept>
#include <string>

using StringDict = std::map<std::string, std::string>;

int EscapeUrlParameter(const char* Parameter, std::string* Result ) {
	// Temporary solution before more secure method is found
	CURL *Curl = curl_easy_init();
	if (Curl) {
		char *Output = curl_easy_escape(Curl, Parameter, 0);
		if (Output) {
			*Result = std::string(Output);
			curl_free(Output);
		}
		curl_easy_cleanup(Curl);
		return (Output ? 0 : 1);
	} else return 1;
}

int VkApiRequest(const char* Method, const StringDict& Arguments, boost::json::value* Result) {
	try {
		auto const Host = "api.vk.com";
		auto const Port = "443";
		std::string ArgumentsString = "";
		for (auto const& [Key, Value] : Arguments) {
			if (ArgumentsString != "") { ArgumentsString.append("&"); }
			ArgumentsString.append(Key);
			ArgumentsString.append("=");
			std::string EncodedValue;
			int CurlErrorCode = EscapeUrlParameter(Value.c_str(), &EncodedValue);
			if (CurlErrorCode) { BOOST_THROW_EXCEPTION(std::runtime_error("CURL error: cannot escape parameter")); }
			ArgumentsString.append(EncodedValue);
		}
		auto const Target = std::string("/method/") + std::string(Method) + std::string("?") + ArgumentsString;
		int Version = 11;
		boost::asio::io_context IOContext;
		boost::asio::ssl::context Context(boost::asio::ssl::context::tlsv12_client);
		load_root_certificates(Context);
		Context.set_verify_mode(boost::asio::ssl::verify_peer);
		boost::asio::ip::tcp::resolver Resolver(IOContext);
		boost::beast::ssl_stream<boost::beast::tcp_stream> Stream(IOContext, Context);
		if (!SSL_set_tlsext_host_name(Stream.native_handle(), Host)) {
			boost::beast::error_code ErrorCode{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
			throw boost::beast::system_error{ErrorCode};
		}
		auto const Results = Resolver.resolve(Host, Port);
		boost::beast::get_lowest_layer(Stream).connect(Results);
		Stream.handshake(boost::asio::ssl::stream_base::client);
		boost::beast::http::request<boost::beast::http::string_body> Request{boost::beast::http::verb::get, Target, Version};
		Request.set(boost::beast::http::field::host, Host);
		Request.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
		boost::beast::http::write(Stream, Request);
		boost::beast::flat_buffer Buffer;
		boost::beast::http::response<boost::beast::http::string_body> Response;
		boost::beast::http::read(Stream, Buffer, Response);
		boost::json::error_code JsonErrorCode;
		boost::json::value ResultJSON = boost::json::parse(Response.body(), JsonErrorCode);
		if (JsonErrorCode) throw boost::json::system_error{JsonErrorCode};
		boost::json::error_code JsonErrorCode2;
		ResultJSON.find_pointer("/error", JsonErrorCode2);
		if (!JsonErrorCode2) {
			std::string ApiErrorCode = std::to_string(ResultJSON.at_pointer("/error/error_code").as_int64());
			auto ApiErrorMsg = ResultJSON.at_pointer("/error/error_msg").as_string();
			BOOST_THROW_EXCEPTION(std::runtime_error(fmt::format("VK API error {}: {}", ApiErrorCode, ApiErrorMsg))); }
		*Result = ResultJSON.at_pointer("/response");
		boost::beast::error_code ErrorCode;
		Stream.shutdown(ErrorCode);
		if (ErrorCode) throw boost::beast::system_error{ErrorCode};
	} catch(std::exception const& Error) {
		std::cerr << "Error: " << Error.what() << std::endl;
		return 1;
	}
	return 0;
}

void HandleGpgError(gpgme_error_t* Error) {
	if (*Error) {
		const char* ErrorMessage = fmt::format("GPG, error {}: {} ({})", *Error, gpgme_strerror(*Error), gpgme_strsource(*Error)).c_str();
		BOOST_LOG_TRIVIAL(error) << ErrorMessage;
		BOOST_THROW_EXCEPTION(std::runtime_error(ErrorMessage));
	}
}

gpgme_error_t SetContext(gpgme_ctx_t* Context) {
	gpgme_check_version(NULL);
	gpgme_error_t Error;
	Error = gpgme_new(Context);
	if (Error) return Error;
	const char* Engine = gpgme_get_dirinfo("gpg-name");
	const char* HomeDir = gpgme_get_dirinfo("homedir");
	Error = gpgme_ctx_set_engine_info(*Context, GPGME_PROTOCOL_OPENPGP, Engine, HomeDir);
	if (Error) return Error;
	gpgme_engine_info_t EngineInfo;
	Error = gpgme_get_engine_info(&EngineInfo);
	if (Error) return Error;
	gpgme_set_armor(*Context, 1);
	gpgme_set_offline(*Context, 1);
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t GetPublicKey(gpgme_ctx_t* Context, const char* Fingerprint, std::string* Key) {
	gpgme_error_t Error;
	gpgme_data_t Keydata;
	Error = gpgme_data_new(&Keydata);
	if (Error) return Error;
	gpgme_key_t Keys[1] = { NULL };
	Error = gpgme_op_export(*Context, Fingerprint, 0, Keydata);
	if (Error) return Error;
	*Key = gpgme_data_release_and_get_mem(Keydata, 0);
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t LoadToken(gpgme_ctx_t* Context, const char* Filename, gpgme_data_t* Token) {
	gpgme_error_t Error;
	gpgme_data_t EncryptedToken;
	Error = gpgme_data_new(&EncryptedToken);
	if (Error) return Error;
	Error = gpgme_data_set_encoding(EncryptedToken, GPGME_DATA_ENCODING_ARMOR);
	if (Error) return Error;
	Error = gpgme_data_new_from_file (&EncryptedToken, Filename, 1);
	if (Error) return Error;
	Error = gpgme_data_new(Token);
	if (Error) return Error;
	Error = gpgme_data_set_encoding(EncryptedToken, GPGME_DATA_ENCODING_BINARY);
	if (Error) return Error;
	Error = gpgme_data_set_flag(*Token, "sensitive", "1");
	if (Error) return Error;
	Error = gpgme_op_decrypt(*Context, EncryptedToken, *Token);
	if (Error) return Error;
	return GPG_ERR_NO_ERROR;
}

// https://github.com/sqlcipher/sqlcipher

int main() {
// 	boost::json::value r;
// 	VkApiRequest("account.getProfileInfo", StringDict{ { "id", "hello world!=&" }, { "foo", "bar" }, }, &r);
// 	std::cout << r << std::endl;
	gpgme_ctx_t GPGContext;
	gpgme_error_t GPGError;
	GPGError = SetContext(&GPGContext);
	gpgme_data_t token;
	GPGError = LoadToken(&GPGContext, "tests/encrypted_token.asc", &token);
	HandleGpgError(&GPGError);
	return 0;
}

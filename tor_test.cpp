#include <curl/curl.h>
#include <iostream>
#include <string>

size_t write_callback(void* contents,
                      size_t size,
                      size_t nmemb,
                      std::string* out)
{
    out->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}


int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <onion_url> <base64_payload>\n";
        return 1;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize libcurl\n";
        return 1;
    }

    std::string response;
    long http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    curl_easy_setopt(curl, CURLOPT_PROXY, "socks5h://127.0.0.1:9050");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, argv[2]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform failed: " << curl_easy_strerror(res) << '\n';
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        std::cout << "HTTP Status: " << http_code << '\n';
        std::cout << "Response:\n" << response << '\n';
    }

    curl_easy_cleanup(curl);
    return 0;
}
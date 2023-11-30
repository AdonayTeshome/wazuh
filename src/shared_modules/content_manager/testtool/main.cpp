#include "contentManager.hpp"
#include "contentRegister.hpp"
#include "defs.h"
#include <chrono>
#include <iostream>
#include <thread>

/*
 * @brief Configuration parameters for the content provider.
 *
 * @topicName: Name of the topic.
 * @interval: Interval in seconds to execute the content provider.
 * @ondemand: If true, the content provider will be executed on demand.
 * @configData: Configuration data to create the orchestration of the content provider.
 * @contentSource: Source of the content.
 * @compressionType: Compression type of the content.
 * @versionedContent: Type of versioned content. If false, the content must not be versioned.
 * @deleteDownloadedContent: If true, the downloaded content will be deleted.
 * @url: URL where the content is located.
 * @outputFolder: if defined, the content will be downloaded to this folder.
 * @dataFormat: Format of the content downloaded or after decompression.
 * @contentFileName: Name for the downloaded file (unless using the 'offline' or 'file' contentSource).
 * @offset (integer): Api offset used to override (if greater) the one set on the database.
 */
static const nlohmann::json CONFIG_PARAMETERS =
    R"(
        {
            "topicName": "test",
            "interval": 10,
            "ondemand": true,
            "configData":
            {
                "contentSource": "cti-snapshot",
                "compressionType": "zip",
                "versionedContent": "false",
                "deleteDownloadedContent": true,
                "url": "https://cti-dev.wazuh.com/api/v1/catalog/contexts/vulnerabilities_ap/consumers/test_ap",
                "outputFolder": "/tmp/testProvider",
                "dataFormat": "json",
                "contentFileName": "example.json",
                "databasePath": "/tmp/content_updater/rocksdb",
                "offset": 0
            }
        }
        )"_json;

int main()
{
    auto& instance = ContentModule::instance();

    // Server
    instance.start(
        [](const int logLevel,
           const std::string& tag,
           const std::string& file,
           const int line,
           const std::string& func,
           const std::string& message)
        {
            auto pos = file.find_last_of('/');
            if (pos != std::string::npos)
            {
                pos++;
            }
            std::string fileName = file.substr(pos, file.size() - pos);

            if (logLevel != LOGLEVEL_ERROR)
            {
                std::cout << tag << ":" << fileName << ":" << line << " " << func << " : " << message.c_str()
                          << std::endl;
            }
            else
            {
                std::cerr << tag << ":" << fileName << ":" << line << " " << func << " : " << message.c_str()
                          << std::endl;
            }
        });
    // CLiente -> vulnenability  detector
    ContentRegister registerer {CONFIG_PARAMETERS.at("topicName").get<std::string>(), CONFIG_PARAMETERS};
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "changing interval" << std::endl;
    registerer.changeSchedulerInterval(10);
    // End client

    std::this_thread::sleep_for(std::chrono::seconds(600));

    // Stop server
    instance.stop();

    return 0;
}

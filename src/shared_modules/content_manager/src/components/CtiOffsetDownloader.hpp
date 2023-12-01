/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 02, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_OFFSET_DOWNLOADER_HPP
#define _CTI_OFFSET_DOWNLOADER_HPP

#include "../sharedDefs.hpp"
#include "CtiDownloader.hpp"
#include "IURLRequest.hpp"
#include "updaterContext.hpp"
#include <algorithm>
#include <sstream>
#include <string>

/**
 * @class CtiOffsetDownloader
 *
 * @brief Class in charge of downloading content offsets from the CTI API as a step of a chain of responsibility.
 *
 */
class CtiOffsetDownloader final : public CtiDownloader
{
private:
    /**
     * @brief Download the content from the API.
     *
     * @param context Updater context.
     */
    void download(UpdaterContext& context) override
    {
        // Set the content type as offset.
        context.data.at("type") = "offsets";

        logDebug2(WM_CONTENTUPDATER, "CtiOffsetDownloader - Starting");
        // Get the parameters needed to download the content.
        getParameters(context);

        // First, make a get request to the API to get the consumer offset.
        const auto consumerLastOffset {getCtiBaseParameters(m_url).lastOffset};

        // Iterate until the current offset is equal to the consumer offset.
        while (context.currentOffset < consumerLastOffset)
        {
            // Amount of offsets to download on each query.
            constexpr auto OFFSETS_DELTA {1000};

            // Calculate the offset to download
            const auto toOffset {std::min(consumerLastOffset, context.currentOffset + OFFSETS_DELTA)};

            // full path where the content will be saved.
            std::ostringstream filePathStream;
            filePathStream << m_outputFolder << "/" << toOffset << "-" << m_fileName;
            const std::string fullFilePath = filePathStream.str();

            // Download the content.
            downloadContent(toOffset, fullFilePath, context);

            // Update the current offset.
            context.currentOffset = toOffset;

            // Save the path of the downloaded content in the context.
            context.data.at("paths").push_back(fullFilePath);
        }

        // Set the status of the stage.
        logDebug2(WM_CONTENTUPDATER, "CtiOffsetDownloader - Finishing");
    }

    /**
     * @brief Get the parameters needed to download the content.
     *
     */
    void getParameters(const UpdaterContext& context)
    {
        // URL of the API to connect to.
        m_url = context.spUpdaterBaseContext->configData.at("url").get<std::string>();

        // Output folder where the file will be saved.
        m_outputFolder = context.spUpdaterBaseContext->downloadsFolder;
        if (context.spUpdaterBaseContext->configData.at("compressionType").get<std::string>().compare("raw") == 0)
        {
            m_outputFolder = context.spUpdaterBaseContext->contentsFolder;
        }

        // name of the file where the content will be saved.
        m_fileName = context.spUpdaterBaseContext->configData.at("contentFileName").get<std::string>();
    }

    /**
     * @brief Download the content from the API.
     *
     * @param toOffset end offset to download.
     * @param fullFilePath full path where the content will be saved.
     */
    void downloadContent(int toOffset, const std::string& fullFilePath, const UpdaterContext& context) const
    {
        // Define the parameters for the request.
        const auto queryParameters =
            "/changes?from_offset=" + std::to_string(context.currentOffset) + "&to_offset=" + std::to_string(toOffset);

        // On download success routine.
        const auto onSuccess {[]([[maybe_unused]] const std::string& data)
                              {
                                  logDebug2(WM_CONTENTUPDATER, "CtiOffsetDownloader - Request processed successfully.");
                              }};

        // Download the content.
        performQueryWithRetry(m_url, onSuccess, queryParameters, fullFilePath);
    }

    std::string m_url {};          ///< URL of the API to connect to.
    std::string m_outputFolder {}; ///< output folder where the file will be saved
    std::string m_fileName {};     ///< name of the file where the content will be saved

public:
    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     */
    explicit CtiOffsetDownloader(IURLRequest& urlRequest)
        : CtiDownloader(urlRequest, "CtiOffsetDownloader")
    {
    }
};

#endif // _CTI_OFFSET_DOWNLOADER_HPP

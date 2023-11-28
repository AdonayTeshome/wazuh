/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_VERSION_UPDATER_HPP
#define _FACTORY_VERSION_UPDATER_HPP

#include "skipStep.hpp"
#include "updateCtiApiOffset.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>
#include <string>

/**
 * @class FactoryVersionUpdater
 *
 * @brief Class in charge of creating the content version updater.
 *
 */
class FactoryVersionUpdater final
{
public:
    /**
     * @brief Creates the content version updater based on the versionedContent value.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(const nlohmann::json& config)
    {

        auto const versionUpdaterType {config.at("versionedContent").get<std::string>()};

        if (versionUpdaterType.compare("cti-api") == 0)
        {
            logDebug2(WM_CONTENTUPDATER, "Creating '%s' version updater", versionUpdaterType.c_str());
            return std::make_shared<UpdateCtiApiOffset>();
        }
        if (versionUpdaterType.compare("false") == 0)
        {
            logDebug2(WM_CONTENTUPDATER, "Version updater not needed");
            return std::make_shared<SkipStep>();
        }
        else
        {
            throw std::invalid_argument {"Invalid 'versionedContent' type: " + versionUpdaterType};
        }
    }
};

#endif // _FACTORY_VERSION_UPDATER_HPP

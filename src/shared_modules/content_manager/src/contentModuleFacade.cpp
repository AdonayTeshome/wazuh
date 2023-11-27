/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentModuleFacade.hpp"
#include "sharedDefs.hpp"

void ContentModuleFacade::start(
    const std::function<
        void(const int, const std::string&, const std::string&, const int, const std::string&, const std::string&)>&
        logFunction)
{
    Log::assignLogFunction(logFunction);
}

void ContentModuleFacade::stop()
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};
    m_providers.clear();
}

void ContentModuleFacade::addProvider(const std::string& name, const nlohmann::json& parameters)
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};
    // If already exist throw exception
    if (m_providers.find(name) != m_providers.end())
    {
        throw std::runtime_error("Provider already exist");
    }

    m_providers.emplace(name, std::make_unique<ContentProvider>(name, parameters));
}

void ContentModuleFacade::startScheduling(const std::string& name, size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        m_providers.at(name)->startActionScheduler(interval);
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "startScheduling: %s", e.what());
    }
}
void ContentModuleFacade::startOndemand(const std::string& name)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        m_providers.at(name)->startOnDemandAction();
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "startOnDemand: %s", e.what());
    }
}

void ContentModuleFacade::changeSchedulerInterval(const std::string& name, const size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        m_providers.at(name)->changeSchedulerInterval(interval);
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "changeSchedulingTime: %s", e.what());
    }
}

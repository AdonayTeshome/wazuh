#ifndef _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H
#define _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H

#include <any>

#include <baseTypes.hpp>
#include <defs/idefinitions.hpp>
#include <sockiface/isockFactory.hpp>
#include <utils/stringUtils.hpp>

#include "expression.hpp"
#include "registry.hpp"

namespace builder::internals::builders
{

namespace ar
{
// TODO: move all the sockets to a shared utils directory
// TODO: when the api is merged these values can be obtained from "base".
constexpr const char* AR_QUEUE_PATH {"/var/ossec/queue/alerts/ar"};

constexpr const char* AGENT_ID_PATH {"/agent/id"};

// TODO: unify these parameters with the api ones
constexpr const char* MODULE_NAME {"wazuh-engine"};

constexpr const char* ORIGIN_NAME {"node01"};

constexpr const char* SUPPORTED_VERSION {"1"};
} // namespace ar

/**
 * @brief Helper Function that allows to send a message through the AR queue.
 * `<field>: +active_response_send/<str>|$<ref>`
 *
 * @param targetField
 * @param rawName
 * @param rawParameters
 * @return base::Expression The lifter with the `active_response_send` transformation.
 */
HelperBuilder getBuilderHelperSendAR(std::shared_ptr<sockiface::ISockFactory> sockFactory);

/**
 * @brief Helper Function for creating the base event that will be sent through
 * Active Response socket with active_response_send
 * ar_message: +active_response_create/<command-name>/<location>/<timeout>/<extra-args>
 *  - <command-name> (mandatory) It can be set directly or through a reference.
 *  - <location>     (mandatory) Accepted values are: "LOCAL", "ALL" or a specific agent
 * id. Such values can be passed directly or through a reference.
 *  - <timeout>      (optional) Timeout value in seconds. It can be passed directly or
 * through a reference.
 *  - <extra-args>   (optional) Reference to an array of *strings*.
 *
 * @param targetField
 * @param rawName
 * @param rawParameters
 * @return base::Expression
 */
base::Expression opBuilderHelperCreateAR(const std::string& targetField,
                                         const std::string& rawName,
                                         const std::vector<std::string>& rawParameters,
                                         std::shared_ptr<defs::IDefinitions> definitions);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H

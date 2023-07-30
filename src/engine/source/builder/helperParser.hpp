#ifndef _BUILDER_HELPER_PARSER_HPP
#define _BUILDER_HELPER_PARSER_HPP

#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include <fmt/format.h>
#include <re2/re2.h>

#include <error.hpp>
#include <json/json.hpp>

#include "syntax.hpp"
#include "utils/stringUtils.hpp"

#include <parsec/parsec.hpp>

namespace builder::internals
{

struct HelperToken
{
    std::string name = "";
    std::vector<std::string> args = {};

    friend std::ostream& operator<<(std::ostream& os, const HelperToken& helperToken)
    {
        std::string separator {};
        separator += syntax::FUNCTION_HELPER_ARG_ANCHOR;

        os << helperToken.name << "(" << base::utils::string::join(helperToken.args, separator, false) << ")";

        return os;
    }
};

inline std::tuple<std::string, json::Json> toBuilderInput(const HelperToken& helperToken,
                                                          const std::string& targetField)
{
    json::Json value {};
    auto valueStr = fmt::format("{}({})", helperToken.name, base::utils::string::join(helperToken.args, ","));
    value.setString(valueStr);

    return std::make_tuple(targetField, std::move(value));
}

inline std::tuple<std::string, json::Json> toBuilderInput(const HelperToken& helperToken)
{
    if (helperToken.args.empty())
    {
        std::stringstream ss {};
        ss << helperToken;
        throw std::runtime_error(
            fmt::format("Helper {} has no arguments, expected to have target field as first argument", ss.str()));
    }

    return toBuilderInput({helperToken.name, {helperToken.args.begin() + 1, helperToken.args.end()}},
                          helperToken.args[0]);
}

// operators (==, !=, <, >, <=, >=)
enum class ExpressionOperator
{
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN,
    LESS_THAN_OR_EQUAL
};



struct ExpressionToken
{
    std::string field;
    ExpressionOperator op;
    json::Json value;
};

using BuildToken = std::variant<HelperToken, ExpressionToken>;

inline parsec::Parser<BuildToken> getTermParser()
{
    std::string helperExtended = syntax::HELPER_NAME_EXTENDED;
    parsec::Parser<std::string> helperNameParser = [helperExtended](auto sv, auto pos) -> parsec::Result<std::string>
    {
        auto next = pos;
        while (next < sv.size() && (std::isalnum(sv[next]) || helperExtended.find(sv[next]) != std::string::npos))
        {
            ++next;
        }

        if (next == pos)
        {
            return parsec::makeError<std::string>("Empty helper name", pos);
        }

        return parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
    };

    parsec::Parser<std::string> parenthOpenParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::PARENTHESIS_OPEN)
        {
            return parsec::makeError<std::string>("Parenthesis open expected", pos);
        }

        return parsec::makeSuccess(std::string(1, syntax::PARENTHESIS_OPEN), pos + 1);
    };

    parsec::Parser<std::string> parenthCloseParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::PARENTHESIS_CLOSE)
        {
            return parsec::makeError<std::string>("Parenthesis close expected", pos);
        }

        return parsec::makeSuccess(std::string(1, syntax::PARENTHESIS_CLOSE), pos + 1);
    };

    parsec::Parser<std::string> argParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        auto next = pos;
        while (next < sv.size())
        {
            // Check for escape sequence
            if (sv[next] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE)
            {
                if (next + 1 < sv.size())
                {
                    // Expecting escapeable character
                    // I think we don't need to scape the whitespace and cut the whitespace at the end before
                    // parenthesis close/arg anchor
                    if (sv[next + 1] == syntax::FUNCTION_HELPER_ARG_ANCHOR || sv[next + 1] == syntax::PARENTHESIS_CLOSE
                        || sv[next + 1] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE || std::isspace(sv[next + 1]))
                    {
                        next += 2;
                    }
                    else
                    {
                        return parsec::makeError<std::string>("Invalid escape sequence", next);
                    }
                }
                else
                {
                    // TODO CHECK if we are here, next shuld increase by 1 or return error
                    return parsec::makeError<std::string>("Invalid escape sequence", next);
                }
            }
            // Check for end of argument
            else if (sv[next] == syntax::FUNCTION_HELPER_ARG_ANCHOR || sv[next] == syntax::PARENTHESIS_CLOSE)
            {
                break;
            }
            // Continue
            else
            {
                ++next;
            }
        }

        return parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
    };

    parsec::Parser<std::string> endArgParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        parsec::Result<std::string> res;
        auto next = pos;
        if (sv[next] == syntax::FUNCTION_HELPER_ARG_ANCHOR)
        {
            // Optional whitespaces (TODO check case ( a    , c    ))
            ++next;
            while (next < sv.size() && std::isspace(sv[next]))
            {
                ++next;
            }

            res = parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
        }
        else if (sv[next] == syntax::PARENTHESIS_CLOSE)
        {
            res = parsec::makeSuccess(std::string(sv.substr(pos, 1)), pos);
        }
        else
        {
            res = parsec::makeError<std::string>("Argument separator or parenthesis close expected", pos);
        }

        return res;
    };

    auto helperArgsParser = parsec::many(argParser << endArgParser);
    auto helperParserRaw = (helperNameParser << parenthOpenParser) & (helperArgsParser << parenthCloseParser);
    auto helperParser = parsec::fmap<HelperToken, std::tuple<std::string, parsec::Values<std::string>>>(
        [](auto&& tuple) -> HelperToken
        {
            HelperToken helperToken;
            helperToken.name = std::get<0>(tuple);
            helperToken.args = std::vector<std::string>(std::get<1>(tuple).begin(), std::get<1>(tuple).end());
            return helperToken;
        },
        helperParserRaw);

    parsec::Parser<json::Json> jsonParser = [](auto sv, auto pos) -> parsec::Result<json::Json>
    {
        if (sv.size() <= pos)
        {
            return parsec::makeError<json::Json>("Empty json", pos);
        }

        rapidjson::Reader reader;
        rapidjson::StringStream ss(sv.substr(pos).data());
        rapidjson::Document doc;

        doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);
        if (doc.HasParseError())
        {
            return parsec::makeError<json::Json>("Error parsing json", pos);
        }

        return parsec::makeSuccess(json::Json (std::move(doc)), pos + ss.Tell());
    };

    // TODO Field name can contains scaped dot, check this
    parsec::Parser<std::string> fieldParser =
        [fieldExtended = std::string(syntax::FIELD_EXTENDED) + syntax::JSON_PATH_SEPARATOR
                         + syntax::FUNCTION_HELPER_DEFAULT_ESCAPE](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::REFERENCE_ANCHOR)
        {
            return parsec::makeError<std::string>("Reference expected", pos);
        }

        auto next = pos + 1;

        while (next < sv.size()
               && (std::isalnum(sv[next]) || fieldExtended.find(sv[next]) != std::string::npos))    // TODO check this
        {
            ++next;
        }

        if (next == pos + 1)
        {
            return parsec::makeError<std::string>("Empty reference", pos);
        }

        return parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
    };

    parsec::Parser<json::Json> valueRefParser = parsec::fmap<json::Json, std::string>(
        [](auto&& str) -> json::Json
        {
            json::Json value;
            value.setString(str);
            return std::move(value);
        },
        fieldParser);

    parsec::Parser<json::Json> wordParser = [](auto sv, auto pos) -> parsec::Result<json::Json>
    {
        auto next = pos;
        while (next < sv.size() && !std::isspace(sv[next]))
        {
            ++next;
        }

        if (next == pos)
        {
            return parsec::makeError<json::Json>("Empty word", pos);
        }

        json::Json word;
        word.setString(sv.substr(pos, next - pos));
        return parsec::makeSuccess(std::move(word), next);
    };

    auto valueParser =  valueRefParser | jsonParser | wordParser;

    parsec::Parser<ExpressionOperator> operatorParser = [](auto sv, auto pos) -> parsec::Result<ExpressionOperator>
    {
        auto next = pos;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        if (next == pos)
        {
            return parsec::makeError<ExpressionOperator>("Empty operator", pos);
        }


        if (next + 1 > sv.size())
        {
            return parsec::makeError<ExpressionOperator>("Operator expected", pos);
        }

        std::vector<std::pair<std::string_view, ExpressionOperator>> compareList = {
            {"==", ExpressionOperator::EQUAL},
            {"!=", ExpressionOperator::NOT_EQUAL},
            {"<=", ExpressionOperator::LESS_THAN_OR_EQUAL},
            {">=", ExpressionOperator::GREATER_THAN_OR_EQUAL},
            {"<", ExpressionOperator::LESS_THAN},
            {">", ExpressionOperator::GREATER_THAN},
        };

        for (auto&& compare : compareList)
        {
            if (sv.substr(next, compare.first.size()) == compare.first)
            {
                return parsec::makeSuccess(ExpressionOperator(compare.second), next + compare.first.size());
            }
        }

        return parsec::makeError<ExpressionOperator>("Unknown operator", pos);

    };

    // <$field><op><value>
    // $field==word
    // $field==$ref
    // $field=="json"

    parsec::Parser<ExpressionToken> expressionParser = parsec::fmap<ExpressionToken, std::tuple<std::tuple<std::string, ExpressionOperator>, json::Json>>(
        [](auto&& tuple) -> ExpressionToken
        {
            ExpressionToken expressionToken;
            expressionToken.field = std::get<0>(std::get<0>(tuple));
            expressionToken.op = std::get<1>(std::get<0>(tuple));
            expressionToken.value = std::move(std::get<1>(tuple));
            return std::move(expressionToken);
        },
        fieldParser & operatorParser & valueParser);

    parsec::Parser<BuildToken> helperParserToken = parsec::fmap<BuildToken, HelperToken>(
        [](auto&& helperToken) -> BuildToken
        {
            return std::move(helperToken);
        },
        helperParser);
    parsec::Parser<BuildToken> expressionParserToken = parsec::fmap<BuildToken, ExpressionToken>(
        [](auto&& expressionToken) -> BuildToken
        {
            return std::move(expressionToken);
        },
        expressionParser);

    parsec::Parser<BuildToken> parser = helperParserToken | expressionParserToken;

    return parser;
}

inline std::variant<HelperToken, base::Error> parseHelper(const std::string& text)
{
    static const auto regexPattern = R"(^([\w_]+)\((.*)\)$)";
    static const re2::RE2 pattern(regexPattern);

    std::string helperName;
    std::string strArgs;

    HelperToken result;

    if (re2::RE2::FullMatch(text, pattern, &result.name, &strArgs))
    {
        if (!strArgs.empty())
        {
            size_t pos = 0;
            while ((pos = strArgs.find(',', pos)) != std::string::npos)
            {
                // if the comma is escaped skip it
                if (pos != 0 && strArgs[pos - 1] == '\\')
                {
                    ++pos;
                    continue;
                }

                // if a space is found after the comma, erase it
                if ((pos + 1) < strArgs.size() && strArgs[pos + 1] == ' ')
                {
                    strArgs.erase(pos + 1, 1);
                }
                // if the space is scaped, delete the backslash
                else if ((pos + 2) < strArgs.size() && strArgs[pos + 1] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE
                         && strArgs[pos + 2] == ' ')
                {
                    strArgs.erase(pos + 1, 1);
                }

                ++pos;
            }

            result.args = base::utils::string::splitEscaped(
                strArgs, syntax::FUNCTION_HELPER_ARG_ANCHOR, syntax::FUNCTION_HELPER_DEFAULT_ESCAPE);
        }

        return result;
    }

    return base::Error {"No match found!"};
}
} // namespace builder::internals

#endif // _BUILDER_HELPER_PARSER_HPP
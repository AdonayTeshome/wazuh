#include <gtest/gtest.h>

#include <re2/re2.h>

#include "helperParser.hpp"

using HelperParserT = std::tuple<bool, std::string, builder::internals::HelperToken>;
class HelperParserTest : public ::testing::TestWithParam<HelperParserT>
{
};

TEST_P(HelperParserTest, parse)
{
    auto &[shouldPass, input, expected] = GetParam();

    auto result = builder::internals::parseHelper(input);

    if (shouldPass)
    {
        ASSERT_TRUE(std::holds_alternative<builder::internals::HelperToken>(result));
        ASSERT_EQ(std::get<builder::internals::HelperToken>(result).name, expected.name);
        ASSERT_EQ(std::get<builder::internals::HelperToken>(result).args, expected.args);
    }
    else
    {
        ASSERT_TRUE(std::holds_alternative<base::Error>(result));
    }
}

INSTANTIATE_TEST_SUITE_P(
    Builder,
    HelperParserTest,
    ::testing::Values(
        HelperParserT(false, "anything", {}),
        HelperParserT(true, "name()", {.name = "name"}),
        HelperParserT(true, "test(arg1)", {.name = "test", .args = {"arg1"}}),
        HelperParserT(true, "test(arg1,arg2)", {.name = "test", .args = {"arg1", "arg2"}}),
        HelperParserT(true, "test(arg1, arg2, arg3)", {.name = "test", .args = {"arg1", "arg2", "arg3"}}),
        HelperParserT(true, "test(arg1, arg2\\,arg3)", {.name = "test", .args = {"arg1", "arg2,arg3"}}),  // Testing escaped comma
        HelperParserT(true, "test(arg1,\\ arg2)", {.name = "test", .args = {"arg1", " arg2"}}),  // Testing escaped space
        HelperParserT(false, "test(arg1", {}),  // Missing closing parenthesis
        HelperParserT(false, "test arg1)", {}),  // Missing opening parenthesis
        HelperParserT(false, "", {}),  // Empty string
        HelperParserT(false, "()", {.name = ""}),  // No function name
        HelperParserT(true, "test(,)", {.name = "test", .args {"", ""}}),
        HelperParserT(true, "test(,,)", {.name = "test", .args {"", "", ""}}),
        HelperParserT(true, "test(, ,)", {.name = "test", .args {"", "", ""}}),
        HelperParserT(true, "test(arg1,)", {.name = "test", .args {"arg1", ""}}),
        HelperParserT(true, "test(arg1, )", {.name = "test", .args {"arg1", ""}}),
        HelperParserT(true, "test(arg1,\\ )", {.name = "test", .args {"arg1", " "}}),
        HelperParserT(true, "test(arg1,  )", {.name = "test", .args {"arg1", " "}}),
        HelperParserT(true, "test(arg1, ())", {.name = "test", .args {"arg1", "()"}}),
        HelperParserT(true, "test(arg1, ( arg2)", {.name = "test", .args = {"arg1", "( arg2"}}),
        HelperParserT(true, "test(arg1, ) arg2)", {.name = "test", .args = {"arg1", ") arg2"}}),
        HelperParserT(true, "test(arg1, ) arg2))))", {.name = "test", .args = {"arg1", ") arg2)))"}})

));


using TermParserT = std::tuple<bool, std::string, builder::internals::BuildToken>;
class TermParserTest : public ::testing::TestWithParam<TermParserT>
{
};

using expToken = builder::internals::ExpressionToken;

TEST_P(TermParserTest, parse)
{

    auto &[shouldPass, input, expected] = GetParam();

    auto result = builder::internals::getTermParser()(input, 0);


    if (shouldPass)
    {
        ASSERT_TRUE(result.success());
        const auto&& resultVToken = result.value();

        // Expression expected
        if (std::holds_alternative<expToken>(expected))
        {
            ASSERT_TRUE(std::holds_alternative<expToken>(resultVToken)) << "Expected ExpressionToken";
            const auto& expectedToken = std::get<expToken>(expected);
            const auto& resultToken = std::get<expToken>(resultVToken);

            ASSERT_EQ(resultToken.op, expectedToken.op);
            ASSERT_EQ(resultToken.field, expectedToken.field);
            ASSERT_EQ(resultToken.value, expectedToken.value);
        }
        else
        {
            FAIL() << "Expected ExpressionToken";
        }
    } else {
        ASSERT_TRUE(result.failure());
    }

}

using eOp = builder::internals::ExpressionOperator;
INSTANTIATE_TEST_SUITE_P(
    Builder,
    TermParserTest,
    ::testing::Values(
        //**************************
        // Expression TEST
        //**************************

        // Expression Ok - with spaces
        TermParserT(true, R"($field == 123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field == "123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field == $field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field == {})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field == null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field == true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field >= 123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field > 123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field <= "123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field < "123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field != $field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field < $field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field == {"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}}),
        // Expression Ok - with spaces after field only
        TermParserT(true, R"($field   ==123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field   =="123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field   ==$field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field   =={})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field   ==null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field   ==true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field   >=123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field   >123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field   <="123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field   <"123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field   !=$field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field   <$field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field =={"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}}),
          // Expression Ok - with spaces after operator only
        TermParserT(true, R"($field==   123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field==  "123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field==   $field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field==   {})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field==   null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field==   true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field>=   123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field>    123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field<=   "123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field<   "123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field!=   $field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field<   $field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field==    {"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}})

        ));
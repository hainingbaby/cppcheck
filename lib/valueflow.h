/*
 * Cppcheck - A tool for static C/C++ code analysis
 * Copyright (C) 2007-2019 Cppcheck team.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
#ifndef valueflowH
#define valueflowH
//---------------------------------------------------------------------------

#include "config.h"

#include <list>
#include <string>
#include <utility>

class ErrorLogger;
class Settings;
class SymbolDatabase;
class Token;
class TokenList;
class Variable;

/* std::pair<first,second> 将两类数据合在一起，当函数需要返回两个数据时可以使用,调用时，pair.first || pair.second.
 * std::list<type> 双向链表，不支持快速随机访问，list.push_front(e)添加元素到list开头，list.push_back(e)添加到结尾.
 * explicit 只对构造函数有效，用来抑制隐式转换，避免出现容易造成误解的隐式类型转换错误.
 * 2019/03/12 @haining
 */
namespace ValueFlow {
    class CPPCHECKLIB Value {
    public:
        typedef std::pair<const Token *, std::string> ErrorPathItem;
        typedef std::list<ErrorPathItem> ErrorPath;
        explicit Value(long long val = 0)
            : valueType(INT),
              intvalue(val),
              tokvalue(nullptr),
              floatValue(0.0),
              moveKind(NonMovedVariable),   // NonMovedVariable, MovedVariable, ForwardedVariable
              varvalue(val),
              condition(nullptr),    //condition为值所依赖的条件
              varId(0U),
              conditional(false),    //conditional value.
              defaultArg(false),    //此值是否作为默认参数传递给函数
              lifetimeKind(Object),  // Object, Lambda, Iterator
              lifetimeScope(Local),  //  Local, Argument 
              valueKind(ValueKind::Possible)  // ValueKind::Possible, ValueKind::Known, ValueKind::Inconclusive
        {}
        Value(const Token *c, long long val);

        bool operator==(const Value &rhs) const {
            if (valueType != rhs.valueType)
                return false;
            switch (valueType) {
            case INT:
                if (intvalue != rhs.intvalue)
                    return false;
                break;
            case TOK:
                if (tokvalue != rhs.tokvalue)
                    return false;
                break;
            case FLOAT:
                // TODO: Write some better comparison
                if (floatValue > rhs.floatValue || floatValue < rhs.floatValue)
                    return false;
                break;
            case MOVED:
                if (moveKind != rhs.moveKind)
                    return false;
                break;
            case UNINIT:
                break;
            case CONTAINER_SIZE:
                if (intvalue != rhs.intvalue)
                    return false;
                break;
            case LIFETIME:
                if (tokvalue != rhs.tokvalue)
                    return false;
            };

            return varvalue == rhs.varvalue &&
                   condition == rhs.condition &&
                   varId == rhs.varId &&
                   conditional == rhs.conditional &&
                   defaultArg == rhs.defaultArg &&
                   valueKind == rhs.valueKind;
        }

        std::string infoString() const;

        enum ValueType { INT, TOK, FLOAT, MOVED, UNINIT, CONTAINER_SIZE, LIFETIME } valueType;
        bool isIntValue() const {
            return valueType == INT;
        }
        bool isTokValue() const {
            return valueType == TOK;
        }
        bool isFloatValue() const {
            return valueType == FLOAT;
        }
        bool isMovedValue() const {
            return valueType == MOVED;
        }
        bool isUninitValue() const {
            return valueType == UNINIT;
        }
        bool isContainerSizeValue() const {
            return valueType == CONTAINER_SIZE;
        }
        bool isLifetimeValue() const {
            return valueType == LIFETIME;
        }

        bool isLocalLifetimeValue() const {
            return valueType == LIFETIME && lifetimeScope == Local;
        }

        bool isArgumentLifetimeValue() const {
            return valueType == LIFETIME && lifetimeScope == Argument;
        }

        /** int value */
        long long intvalue;

        /** token value - the token that has the value. this is used for pointer aliases, strings, etc. */
        const Token *tokvalue;

        /** float value */
        double floatValue;

        /** kind of moved  */
        enum MoveKind {NonMovedVariable, MovedVariable, ForwardedVariable} moveKind;

        /** For calculated values - variable value that calculated value depends on */
        long long varvalue;

        /** Condition that this value depends on */
        const Token *condition;

        ErrorPath errorPath;

        /** For calculated values - varId that calculated value depends on */
        unsigned int varId;

        /** Conditional value */
        bool conditional;

        /** Is this value passed as default parameter to the function? */
        bool defaultArg;

        enum LifetimeKind {Object, Lambda, Iterator} lifetimeKind;

        enum LifetimeScope { Local, Argument } lifetimeScope;

        static const char * toString(MoveKind moveKind) {
            switch (moveKind) {
            case NonMovedVariable:
                return "NonMovedVariable";
            case MovedVariable:
                return "MovedVariable";
            case ForwardedVariable:
                return "ForwardedVariable";
            }
            return "";
        }

        /** How known is this value */
        enum class ValueKind {
            /** This value is possible, other unlisted values may also be possible */
            Possible,
            /** Only listed values are possible */
            Known,
            /** Inconclusive */
            Inconclusive
        } valueKind;

        void setKnown() {
            valueKind = ValueKind::Known;
        }

        bool isKnown() const {
            return valueKind == ValueKind::Known;
        }

        void setPossible() {
            valueKind = ValueKind::Possible;
        }

        bool isPossible() const {
            return valueKind == ValueKind::Possible;
        }

        void setInconclusive(bool inconclusive = true) {
            if (inconclusive)
                valueKind = ValueKind::Inconclusive;
        }

        bool isInconclusive() const {
            return valueKind == ValueKind::Inconclusive;
        }

        void changeKnownToPossible() {
            if (isKnown())
                valueKind = ValueKind::Possible;
        }

        bool errorSeverity() const {
            return !condition && !defaultArg;
        }
    };

    /// Constant folding of expression. This can be used before the full ValueFlow has been executed (ValueFlow::setValues).
    const ValueFlow::Value * valueFlowConstantFoldAST(const Token *expr, const Settings *settings);

    /// Perform valueflow analysis.
    void setValues(TokenList *tokenlist, SymbolDatabase* symboldatabase, ErrorLogger *errorLogger, const Settings *settings);

    std::string eitherTheConditionIsRedundant(const Token *condition);
}

const Variable *getLifetimeVariable(const Token *tok, ValueFlow::Value::ErrorPath &errorPath);

std::string lifetimeType(const Token *tok, const ValueFlow::Value *val);

#endif // valueflowH

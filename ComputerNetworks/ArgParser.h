#ifndef __ARGPARSER_H
#define __ARGPARSER_H

#include "types.h"
#include <map>

/*class CN_DLLSPEC InvalidArgumentException
{
public:
    InvalidArgumentException(string& errorStr) : m_string(errorStr) { }
    
    string getErrorString() const
    {
        return m_string;
    }

private:
    string m_string;
};*/

class CN_DLLSPEC ArgParser
{
public:
    ArgParser();

    void addArgument(string argument, string description = "", string defaultValue = "", bool mandatory = false, bool simple = false);
    bool parseArguments(uint32 argc, char** argv);
    bool allRequiredFieldsFilled() const;

    string getString(string argument) const;
    bool isTrue(string argument) const;

    void showHelp() const;

private:
    struct Argument {
        string value;
        string description;
        bool mandatory;
        bool simple;
    };

    typedef map<string, Argument> ArgumentMap;

    ArgumentMap m_arguments;
};

#endif

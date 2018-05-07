#include "ArgParser.h"
#include <iostream>

ArgParser::ArgParser()
{
    addArgument("help", "Shows help", "", false, true);
}

void ArgParser::addArgument(string argument, string description, string defaultValue, bool mandatory, bool simple)
{
    Argument arg;
    arg.value = defaultValue;
    arg.description = description;
    arg.mandatory = mandatory;
    arg.simple = simple;

    m_arguments.insert(pair<string, Argument>(argument, arg));
}

bool ArgParser::parseArguments(uint32 argc, char** argv)
{
    if (argc <= 1)
        return true;
    
    argc--;

    for (uint32 i = 0; i < argc; i += 2)
    {
        string argName = argv[i + 1];
        while (argName[0] == '-')
            argName = argName.substr(1);

        ArgumentMap::iterator it = m_arguments.find(argName);
        if (it == m_arguments.end())
            return false;

        if (it->second.simple)
        {
            it->second.value = "true";
            i--;
        }
        else
        {
            if (i + 2 >= argc)
                return false;

            it->second.value = argv[i + 2];
        }
    }
    
    if (isTrue("help"))
    {
        showHelp();
        return false;
    }

    return true;
}

string ArgParser::getString(string argument) const
{
    ArgumentMap::const_iterator it = m_arguments.find(argument);
    if (it == m_arguments.end())
        return "";

    return it->second.value;
}

bool ArgParser::isTrue(string argument) const
{
    string arg = getString(argument);

    if (arg.empty() || arg == "0")
        return false;

    if (arg == "1" || arg == "true" || arg == "TRUE")
        return true;

    return false;
}

bool ArgParser::allRequiredFieldsFilled() const
{
    ArgumentMap::const_iterator it = m_arguments.begin();
    for (; it != m_arguments.end(); it++)
    {
        if (it->second.mandatory && it->second.value.length() == 0)
            return false;
    }

    return true;
}

void ArgParser::showHelp() const
{
    cout << "Description of program arguments:" << endl;

    ArgumentMap::const_iterator it = m_arguments.begin();
    for (; it != m_arguments.end(); it++)
    {
        cout << " -" << it->first.c_str() << " ";
        if (!it->second.simple)
            cout << "<value> ";

        cout << it->second.description.c_str();

        if (it->second.mandatory)
            cout << " [mandatory]";
        if (it->second.value.length() && it->first != "help")
            cout << " [default value: " << it->second.value.c_str() << "]";

        cout << endl;
    }
}

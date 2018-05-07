#include "tcp.h"

string TCPHeader::getFlags() const
{
    string flagsStr;

    if (hasFlag(Syn)) flagsStr += "Syn ";
    if (hasFlag(Fin)) flagsStr += "Fin ";
    if (hasFlag(Ack)) flagsStr += "Ack ";
    if (hasFlag(Rst)) flagsStr += "Rst ";
    if (hasFlag(Psh)) flagsStr += "Psh ";
    if (hasFlag(Urg)) flagsStr += "Urg ";

    return flagsStr;
}

#ifndef __ICALLBACK_H
#define __ICALLBACK_H

#include <cstdlib>

class ICallback
{
public:
    virtual void call(void* data) = 0;
};

class CallbackHandler
{
public:
    CallbackHandler() : m_callback(NULL) { }
    CallbackHandler(ICallback* callback) : m_callback(callback) { }

    void setCallback(ICallback* callback)
    {
        m_callback = callback;
    }

    void call(void* data)
    {
        if (m_callback)
            m_callback->call(data);
    }

private:
    ICallback* m_callback;
};

#endif

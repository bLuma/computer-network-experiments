#ifndef __THREAD_H
#define __THREAD_H

#include "types.h"
#include <Windows.h>

class CN_DLLSPEC Runnable
{
public:
    virtual void run() = 0;
};

class CN_DLLSPEC Thread 
{
public:
    Thread(Runnable* runnable) : m_runnable(runnable), m_deleteOnEnd(true) { }
    Thread(Runnable* runnable, bool deleteOnEnd) : m_runnable(runnable), m_deleteOnEnd(deleteOnEnd) { }

    void start() 
    {
        ThreadData* param = new ThreadData;
        param->runnable = m_runnable;
        param->deleteOnEnd = m_deleteOnEnd;

        m_threadHandle = CreateThread(NULL, 0, &(Thread::launchThread), param, 0, &m_threadId);
    }

    void setDeleteOnEnd(bool deleteonend)
    {
        m_deleteOnEnd = deleteonend;
    }

    void join()
    {
        WaitForSingleObject(m_threadHandle, INFINITE);
    }

private:
    static DWORD WINAPI launchThread(LPVOID lpThreadParameter)
    {
        if (!lpThreadParameter)
            throw "Thread error";

        ThreadData* params = (ThreadData*)lpThreadParameter;

        params->runnable->run();

        if (params->deleteOnEnd)
        {
            delete params->runnable;
            params->runnable = NULL;
        }

        delete params;

        return 0;
    }

    struct ThreadData
    {
        Runnable* runnable;
        bool deleteOnEnd;
    };

    Runnable* m_runnable;
    bool m_deleteOnEnd;
    DWORD m_threadId;
    HANDLE m_threadHandle;
};

#endif

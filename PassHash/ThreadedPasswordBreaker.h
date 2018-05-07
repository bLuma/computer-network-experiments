#ifndef __THREADEDPASSWORDBREAKER_H
#define __THERADEDPASSWORDBREAKER_H

#include "PasswordBreaker.h"
#include <Thread.h>
#include <ICallback.h>

class CN_DLLSPEC ThreadedPasswordBreaker : public PasswordBreaker, public Runnable
{
public:
    void setCallback(ICallback* callback)
    {
        m_callback.setCallback(callback);
    }

    virtual void crack();
    virtual void run();

private:
    CallbackHandler m_callback;
};

#endif

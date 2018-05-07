#include "ThreadedPasswordBreaker.h"

void ThreadedPasswordBreaker::crack()
{
    Thread thread(this, false);

    thread.start();
}

void ThreadedPasswordBreaker::run()
{
    PasswordBreaker::crack();
    
    m_callback.call((void*)this);
}

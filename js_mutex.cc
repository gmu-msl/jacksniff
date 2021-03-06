/*
 * Copyright (c) 2008,2009, University of California, Los Angeles and 
 * Colorado State University All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of NLnetLabs nor the names of its
 *       contributors may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "js_mutex.h"
#include "js_defs.h"

JsMutex::JsMutex()
{
  int iErr = pthread_mutex_init(&m_tMutex, NULL);
  if (0 != iErr)
  {
    js_log("Unable to init mutex: %s\n", strerror(iErr));
  }

  iErr = pthread_cond_init(&m_tCond, NULL);
  if (0 != iErr)
  {
    js_log("Unable to init cond: %s\n", strerror(iErr));
  }
}

JsMutex::~JsMutex()
{
  pthread_mutex_destroy(&m_tMutex);
  pthread_cond_destroy(&m_tCond);
}

bool JsMutex::lock()
{
  bool bRet = false;

  int iErr = pthread_mutex_lock(&m_tMutex);
  if (0 != iErr)
  {
    js_log("Unable to lock mutex: %s\n", strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}

bool JsMutex::unlock()
{
  bool bRet = false;

  int iErr = pthread_mutex_unlock(&m_tMutex);
  if (0 != iErr)
  {
    js_log("Unable to unlock mutex: %s\n", strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}

bool JsMutex::wait(long p_lMillis /*= 0*/)
{
  bool bRet = false;

  int iErr = 0;
  if (0 == p_lMillis)
  {
    iErr = pthread_cond_wait(&m_tCond, &m_tMutex);
  }
  else
  {
    struct timespec tSpec;
    tSpec.tv_sec = time(NULL) + ((int) (p_lMillis/1000));
    tSpec.tv_nsec = p_lMillis % 1000;

    iErr = pthread_cond_timedwait(&m_tCond, &m_tMutex, &tSpec);
  }

  if (0 != iErr && ETIMEDOUT != iErr)
  {
    js_log("Unable to wait: %s\n", strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}

bool JsMutex::signal()
{
  bool bRet = false;

  int iErr = pthread_cond_signal(&m_tCond);
  if (0 != iErr)
  {
    js_log("Unable to signal: %s\n", strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}

bool JsMutex::signalAll()
{
  bool bRet = false;

  int iErr = pthread_cond_broadcast(&m_tCond);
  if (0 != iErr)
  {
    js_log("Unable to broadcast: %s\n", strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}


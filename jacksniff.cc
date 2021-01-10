#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <vantages/dns_resolver.h>
#include <vantages/dns_task.h>
#include <vantages/dns_err.h>

#include "js_pcap.h"
#include "js_task.h"
#include "js_defs.h"

using namespace std;

void _usage()
{
  fprintf(stdout, "jacksniff -n <network> -q <DNS fqdn query> [ -c <concurrency> ] [ -l <loops per IP> ] [ -o <output file> ] | -h\n");
}

bool _covered(in_addr_t p_tAddr, struct in_addr p_tNet, int p_iMaskLen)
{
  p_tNet.s_addr = ntohl(p_tNet.s_addr);
  p_tAddr = ntohl(p_tAddr);
  p_tNet.s_addr >>= (32 - p_iMaskLen);
  p_tAddr >>= (32 - p_iMaskLen);

  return (p_tNet.s_addr == p_tAddr);
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  char *szNet = NULL;
  int iMaskLen = 32;
  struct in_addr tAddr;
  memset(&tAddr, 0, sizeof(tAddr));

  int iConcurrency = 20;
  int iLoops = 1;
  char *szOutFile = NULL;
  char *szQuery = NULL;

  int c = 0;
  while ((c = getopt(argc, argv, "n:l:c:o:q:h")) != -1)
  {
    switch(c)
    {
      case 'n':
        szNet = optarg;
        iMaskLen = inet_net_pton(AF_INET, szNet, &tAddr, sizeof(tAddr));
        if (-1 == iMaskLen)
        {
          js_log("Unable to convert %s to network: %s\n", szNet, strerror(errno));
        }
        break;
      case 'c':
        iConcurrency = (int) strtol(optarg, NULL, 10);
        break;
      case 'l':
        iLoops = (int) strtol(optarg, NULL, 10);
        break;
      case 'o':
        szOutFile = optarg;
        break;
      case 'q':
        szQuery = optarg;
        break;
      case 'h':
        _usage();
        exit(0);
        break;
      default:
        _usage();
        exit(1);
        break;
    }
  }

  if (NULL == szNet)
  {
    js_log("Must specify network.\n");
    _usage();
  }
  else if (0 == iConcurrency)
  {
    js_log("Must specify valid Concurrency.\n");
    _usage();
  }
  else if (0 == iLoops)
  {
    js_log("Must specify valid number of loops.\n");
    _usage();
  }
  else if (NULL == szQuery)
  {
    js_log("Must specify query.\n");
    _usage();
  }
  else
  {
    FILE *pOutFile = stdout;
    if (NULL != szOutFile)
    {
      if (NULL == (pOutFile = fopen(szOutFile, "w")))
      {
        js_log("Unable to open output file '%s' for writing.\n", szOutFile);
      }
    }

    if (NULL != pOutFile)
    {
      DnsResolver oRes;
      oRes.setConcurrency(iConcurrency);
      oRes.setRetries(1);

      JsPcap oPcap;

      if (!oPcap.initPcap(pOutFile, szNet, szQuery))
      {
        js_log("Unable to init pcap.\n");
      }
      else
      {
        oPcap.start();
        sleep(1);

        struct in_addr tTmpAddr;
        memset(&tTmpAddr, 0, sizeof(tTmpAddr));

        time_t tLastCheck = 0;

        in_addr_t t = tAddr.s_addr;
        while (_covered(t, tAddr, iMaskLen))
        {
          DnsTask *pTmpTask = NULL;
          for (int i = 0;
               i < iConcurrency
               && oRes.hasTasks()
               && NULL != (pTmpTask = oRes.recv());
               i++)
          {
            delete pTmpTask;
          }

          for (int j = 0;
               j < iConcurrency
               && _covered(t, tAddr, iMaskLen)
               && oRes.hasRoomToSend();
               t = htonl(ntohl(t) + 1))
          {
            JackSniffTask *pTask = new JackSniffTask(szQuery, ntohl(t));
            struct timeval tNow;
            memset(&tNow, 0, sizeof(tNow));
            gettimeofday(&tNow, NULL);
            string sKey = DnsResolver::makeKey(*(pTask->getQuery()), ntohl(t));
            oPcap.addQuery(sKey, tNow);
            if (!oRes.send(pTask))
            {
              js_log("Unable to send task: %s\n", DnsError::getInstance().getError().c_str());
              delete pTask;
            }

            if (tNow.tv_sec > (tLastCheck + 300))
            {
              oPcap.timeoutKeys();
              tLastCheck = tNow.tv_sec;
            }
          }
        }

        iRet = 0;
        sleep(1);
      }
    }
  }

  return iRet;
}

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
// #include <net/if_types.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <pthread.h>

#include <sstream>

#include <vantages/dns_packet.h>
#include <vantages/dns_rr.h>
#include <vantages/dns_a.h>
#include <vantages/dns_resolver.h>
#include <vantages/dns_name.h>

#include "js_pcap.h"
#include "js_mutex_hdlr.h"
#include "js_defs.h"

using namespace std;

void *_start(void *p_pJsPcap)
{
  JsPcap *pPcap = (JsPcap *) p_pJsPcap;

  if (NULL == pPcap)
  {
    js_log("pcap class is NULL!\n");
  }
  else
  {
    pPcap->run();
  }

  return NULL;
}

void _get_response(unsigned char *p_pJsPcap,
                   const struct pcap_pkthdr *p_pHdr,
                   const unsigned char *p_pPkt)
{
  uint16_t uType = ntohs(((struct ether_header *) p_pPkt)->ether_type);
  if (ETHERTYPE_IP != uType)
  {
    js_log("Incorrect ETHERTYPE: 0x%x\n", uType);
  }
  else
  {
    struct ip *pIP = (struct ip *) (p_pPkt + sizeof(struct ether_header));
    if (4 != (pIP->ip_v & 0x00ff))
    {
      js_log("Got IP header version: %u (not 4)\n", (pIP->ip_v & 0x00ff));
    }
    else if (5 > (pIP->ip_hl & 0x00ff))
    {
      js_log("Header len is too short: %u\n", pIP->ip_hl & 0x00ff);
    }
    else if (pIP->ip_hl >= ntohs(pIP->ip_len))
    {
      js_log("Header as long or longer than packet? %u >= %u\n", pIP->ip_hl, ntohs(pIP->ip_len));
    }
    else if (IPPROTO_UDP != pIP->ip_p)
    {
      js_log("Only processing UDP for now.\n");
    }
    else
    {
      size_t uHdrLen = pIP->ip_hl * 4;
      size_t uDataLen = ntohs(pIP->ip_len) - uHdrLen - sizeof(struct udphdr);
      u_char *pPkt = (u_char *) (p_pPkt + sizeof(struct ether_header) + uHdrLen + sizeof(udphdr));
      RRList_t tRRs;
      RRIter_t tIter;
      DnsPacket oPkt;
      JsPcap *pPcap = (JsPcap *) p_pJsPcap;

      if (!oPkt.fromWire(pPkt, uDataLen))
      {
        js_log("Unable to create packet.\n");
      }
      else if (!pPcap->log(pIP, oPkt))
      {
        js_log("Unable to format string.\n");
      }
    }
  }
}

uint16_t _checksum(uint16_t *p_pBuff, int p_iSize)
{
  register long lSum = 0;
  for (lSum = 0; p_iSize > 0; p_iSize -= 2)
  {
    lSum += *p_pBuff++;
  }

  lSum = (lSum >> 16) + (lSum & 0xFFFF);
  lSum += (lSum >> 16);

  return ~lSum;
}

uint16_t _udpChecksum(char *p_pBuff)
{
  uint16_t uRet = 0xffff;

  struct ip *pIP = (struct ip *) p_pBuff;
  if (NULL == p_pBuff)
  {
    js_log("NULL buffer.\n");
  }
  else if (IPPROTO_UDP != pIP->ip_p)
  {
    js_log("Wrong protocol %u != UDP\n", pIP->ip_p);
  }
  else
  {
    int iHeaderLen = pIP->ip_hl * 4;
    int iLen = ntohs(pIP->ip_len);
    struct udphdr *pUDP = (struct udphdr *) &(p_pBuff[iHeaderLen]);
    uint16_t uOldSum = pUDP->uh_sum;
    pUDP->uh_sum = 0;

    js_pseudo_hdr_t tPHdr;
    memset(&tPHdr, 0, sizeof(tPHdr));

    tPHdr.m_uSrcIP = pIP->ip_src.s_addr;
    tPHdr.m_uDstIP = pIP->ip_dst.s_addr;
    tPHdr.m_uProto = pIP->ip_p;
    tPHdr.m_uLen = htons(iLen - iHeaderLen);
    int iNewLen = iLen - iHeaderLen + sizeof(tPHdr);
    char *pBuff = new char[iNewLen];
    memset(pBuff, 0, iNewLen);
    memcpy(pBuff, &tPHdr, sizeof(tPHdr));
    memcpy(&(pBuff[sizeof(tPHdr)]), pUDP, iLen - iHeaderLen);
    uint16_t uCalcSum = _checksum((uint16_t *)pBuff, iNewLen);
    pUDP->uh_sum = uOldSum;

    if (uOldSum != uCalcSum)
    {
      uRet = uCalcSum;
    }
    else
    {
      uRet = 0;
    }

    delete[] pBuff;
  }

  return uRet;
}


JsPcap::JsPcap()
  : m_bInit(false),
    m_bRun(false),
    m_pLog(NULL),
    m_pHandle(NULL)
{
  memset(&m_tProg, 0, sizeof(m_tProg));
}

JsPcap::~JsPcap()
{
  m_bInit = false;
  m_bRun = false;
  if (NULL != m_pHandle)
  {
    pcap_close(m_pHandle);
//    m_pHandle = NULL;
  }

  pcap_freecode(&m_tProg);
}

bool JsPcap::initPcap(FILE *p_pLog, const char *p_szNet, const char *p_szName)
{
  bool bRet = false;

  bpf_u_int32 uNet;
  bpf_u_int32 uMask;

  string sProgram = "src net ";
  sProgram += p_szNet;
  sProgram += " and udp";

  const char *szDev = NULL;
//  szDev = "en1";
  char szErrBuff[PCAP_ERRBUF_SIZE];
  memset(szErrBuff, 0, PCAP_ERRBUF_SIZE);
  memset(&m_tProg, 0, sizeof(m_tProg));

  m_bInit = false;

  if (NULL == p_szNet)
  {
    js_log("Cannot init with NULL net.\n");
  }
  else if (NULL == p_szName)
  {
    js_log("Cannot init with NULL name.\n");
  }
  else if (NULL == p_pLog)
  {
    js_log("Unable to init with NULL log file.\n");
  }
  else if (NULL == szDev
           && NULL == (szDev = pcap_lookupdev(szErrBuff)))
  {
    js_log("Unable to lookup pcap device: '%s'\n",
           szErrBuff);
  }
  else if (-1 == pcap_lookupnet((char *) szDev, &uNet, &uMask, szErrBuff))
  {
    js_log("Unable to lookup net and mask: '%s'\n", szErrBuff);
  }
  else if (NULL == (m_pHandle = pcap_open_live((char *) szDev, JS_PCAP_BUFF_SIZE, 0, 50, szErrBuff)))
  {
    js_log("Unable to open live pcap handle: %s\n", szErrBuff);
  }
  else if (-1 == pcap_compile(m_pHandle, &m_tProg, (char *) sProgram.c_str(), 0, uNet))
  {
    js_log("Unable to compile program: '%s'\n", sProgram.c_str());
  }
  else if (-1 == pcap_setfilter(m_pHandle, &m_tProg))
  {
    js_log("Unable to set filter.\n");
  }
  else
  {
    m_sName = p_szName;
    m_sNet = p_szNet;
    m_pLog = p_pLog;
    m_bRun = true;
    m_bInit = true;
    bRet = true;
  }

  return bRet;
}

bool JsPcap::start()
{
  bool bRet = false;

  int iErr = pthread_create(&m_tID, NULL, _start, (void *) this);
  if (0 != iErr)
  {
    js_log("Unable to start pcap listener: %s\n", strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}

void JsPcap::run()
{
  if (m_bInit)
  {
    while (m_bRun)
    {
      pcap_loop(m_pHandle, 1, _get_response, (unsigned char *) this);
    }
  }
}

void JsPcap::kill()
{
  m_bRun = false;
}

void JsPcap::addQuery(std::string &p_sKey, struct timeval &p_tTime)
{
  {
    JsMutexHandler oMH(m_oMutex);
    m_oKeyMap[p_sKey] = p_tTime;
  }
}

bool JsPcap::getTime(std::string &p_sKey, struct timeval &p_tTime)
{
  bool bRet = false;

  {
    JsMutexHandler oMH(m_oMutex);
    key_iter_t tIter = m_oKeyMap.find(p_sKey);
    if (m_oKeyMap.end() == tIter)
    {
      js_log("Could not find time map entry for key '%s'\n", p_sKey.c_str());
    }
    else
    {
      p_tTime = tIter->second;
      bRet = true;
    }
  }

  return bRet;
}

void JsPcap::timeoutKeys()
{
  time_t tNow = time(NULL);
  {
    JsMutexHandler oMH(m_oMutex);
    for (key_iter_t tIter = m_oKeyMap.begin();
         m_oKeyMap.end() != tIter;
         tIter++)
    {
      struct timeval *p = &(tIter->second);
      if (p->tv_sec < (tNow - 300))
      {

        m_oKeyMap.erase(tIter);
      }
    }
  }
}

bool JsPcap::log(struct ip *p_pIP, DnsPacket &p_oPkt)
{
  bool bRet = false;

  if (NULL == p_pIP)
  {
    js_log("Unable to log with NULL IP header.\n");
  }
  else
  {
    struct timeval tNow;
    
    string sKey = DnsResolver::makeKey(p_oPkt, ntohl(p_pIP->ip_src.s_addr));
    struct timeval tWhen;
    RRList_t tAs;
    char pIP[16] = {0};
    const char *szIP = inet_ntop(AF_INET, &(p_pIP->ip_src), pIP, 16);

    if (NULL == szIP)
    {
      js_log("Unable to convert IP to IP: %s\n", strerror(errno));
    }
    else if (0 != gettimeofday(&tNow, NULL))
    {
      js_log("Unable to get current time: %s\n", strerror(errno));
    }
    else if (!getTime(sKey, tWhen))
    {
      js_log("Could not find time for key '%s'\n", sKey.c_str());
    }
    else if (!p_oPkt.getAnswers(tAs))
    {
      js_log("Unable to get answer section from packet\n");
    }
    else
    {
      int iTime = (tNow.tv_sec - tWhen.tv_sec) * 1000;
      iTime += ((tNow.tv_usec - tWhen.tv_usec) / 1000);

      uint16_t uSum = _udpChecksum((char *) p_pIP);

      ostringstream oPrint;
      if (tAs.empty())
      {
          oPrint << szIP
                 << "\t"
                 << (int) p_pIP->ip_ttl
                 << "\t"
                 << uSum
                 << "\t"
                 << iTime
                 << "\t"
                 << m_sName
                 << "\t"
                 << p_oPkt.getHeader().rcode()
                 << "\t"
                 << "-"
                 << "\t"
                 << "-"
                 << "\t"
                 << "-"
<< "\t" << sKey
                 << "\n";

      }
      else
      {
        for (RRIter_t tIter = tAs.begin();
             tAs.end() != tIter;
             tIter++)
        {
          DnsRR *pRR = *tIter;

          char pAddr[16] = {0};
          const char *szAddr = NULL;
          if (pRR->type() == DNS_RR_A)
          {
            uint32_t uIP = htonl(((DnsA *) pRR)->ip());
            szAddr = inet_ntop(AF_INET, &uIP, pAddr, 16);
          }
          string sName = pRR->get_name()->toString();
          oPrint << szIP
                 << "\t"
                 << (int) p_pIP->ip_ttl
                 << "\t"
                 << uSum
                 << "\t"
                 << iTime
                 << "\t"
                 << m_sName
                 << "\t"
                 << p_oPkt.getHeader().rcode()
                 << "\t"
                 << sName
                 << "\t"
                 << pRR->ttl()
                 << "\t";
          oPrint << ((NULL != szAddr) ? szAddr : "-")
                 << "\t" 
                 << sKey
                 << "\n";

        }
      }
      fprintf(m_pLog, "%s", oPrint.str().c_str());

      bRet = true;
    }
  }

  return bRet;
}

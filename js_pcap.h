#ifndef _JS_PCAP_H
#define _JS_PCAP_H

#include <pcap.h>
#include <sys/time.h>
#include <netinet/ip.h>

#include <map>
#include <string>

#include "js_mutex.h"

class DnsPacket;

class JsPcap
{
  // Types and enums
  public:
    typedef std::map<std::string, struct timeval> key_map_t;
    typedef key_map_t::iterator key_iter_t;

  // Member Variables
  private:
    bool m_bInit;
    bool m_bRun;
    FILE *m_pLog;
    pcap_t *m_pHandle;
    pthread_t m_tID;
    struct bpf_program m_tProg;
    std::string m_sName;
    std::string m_sNet;
    JsMutex m_oMutex;
    key_map_t m_oKeyMap;

  // Methods
  public:
    JsPcap();
    virtual ~JsPcap();
    bool initPcap(FILE *p_pLog, const char *p_szNet, const char *p_szName);
    bool start();
    void run();
    void kill();
    void addQuery(std::string &p_sKey, struct timeval &p_tTime);
    bool getTime(std::string &p_sKey, struct timeval &p_tTime);
    void timeoutKeys();
    bool log(struct ip *p_pIP, DnsPacket &p_oPkt);
};

#endif

# jacksniff

# Table of Contents

* [Compiling](#compiling)
* [Dependencies](#dependencies)
* [Executable](#executable)
* [Example Output](#examples)


#<a name="compiling"></a>
Compiling jacksniff
===========

```
make
```

#<a name="dependencies"></a>
Dependencies
======

To compile jacksniff, there are a couple of dependencies: libpcap, and libvdns.
The first, libpcap, can be installed in numerous ways (described below).  The second,
libvdns, is part of the open source [Vantages DNS library](https://gitlab.com/ginipginob/vantages).

## Vantages (libvdns)
To install Vantages, follow its directions **but** you only need its DNS library.  To expedite installation and minimize other
dependencies, you can configure it with:

```
./configure --without-vantaged
make
sudo make install
```

## libpcap
To install libpcap:

Redhat/CentOS/Fedora
----

```
sudo yum install libpcap-devel
```

Mac OS X
---
If you use ports:
```
sudo port install libpcap
```

Ubuntu / Debian
---

```
sudo apt-get install libpcap-dev
```

#<a name="example"></a>
Example
======

The output from jacksniff is a tab delimited line for each IP address that responded to a query.  For example, if you wanted to examine which
IP addresses in 1.1.1.0/24 would respond to DNS queries (and what the responses looked like), you could run (using, for example, www.facebook.com):

```
$ sudo ./jacksniff -n 1.1.1.0/24 -q www.facebook.com
```

The output on each line would, then, be a tab-delimited list of:
* Responding IP: Since jacksniff is designed to scan an IP prefix, each responding IP address is identified.  
* IP header TTL: The observed IP TTL.
* IP checksum: The observed value in the IP header.
* Round-Trip-Time (RTT): The amount of time (in msec) that elapsed between sending the query and receiving each response (there can be more than one response from a given IP).
* DNS qname: The query name sent (which may, or may not, be the same as the name of RRs in the response).
* DNS RCODE: The Response Code returned in the DNS header
* DNS domain name response: The domain name **in** the DNS resonse.
* DNS TTL: The TTL value of the DNS response(s).
* A record value: The IP address in a DNS response (if the answer was an A record).
* An internal cache key: This is an internal debugging value for jacksniff.



For example, the above might net the following output:
```
1.1.1.3	60	0	60	www.facebook.com	0	www.facebook.com.	3591	-	www.facebook.com.|1|1|1397|16843011|0
1.1.1.3	60	0	60	www.facebook.com	0	star-mini.c10r.facebook.com.	51	31.13.66.35	www.facebook.com.|1|1|1397|16843011|0
1.1.1.2	60	0	61	www.facebook.com	0	www.facebook.com.	3593	-	www.facebook.com.|1|1|63438|16843010|0
1.1.1.2	60	0	61	www.facebook.com	0	star-mini.c10r.facebook.com.	53	31.13.66.35	www.facebook.com.|1|1|63438|16843010|0
1.1.1.1	60	0	61	www.facebook.com	0	www.facebook.com.	3589	-	www.facebook.com.|1|1|32142|16843009|0
1.1.1.1	60	0	61	www.facebook.com	0	star-mini.c10r.facebook.com.	49	31.13.66.35	www.facebook.com.|1|1|32142|16843009|0
```

Which would be interpretted as:

| Resp. IP | IP TTL | checksum | RTT (msec) | DNS qname | DNS RCODE | DNS response name | DNS TTL | Answer from A record) | an internal cache key |
| --- | --- | --- |--- |--- |--- |--- |--- |--- |--- |
| 1.1.1.3 | 60 | 0 | 60 | www.facebook.com | 0 | www.facebook.com. | 3591 | - | www.facebook.com.\|1\|1\|1397\|16843011\|0
| 1.1.1.3 | 60 | 0 | 60 | www.facebook.com | 0 | star-mini.c10r.facebook.com. | 51 | 31.13.66.35 | www.facebook.com.\|1\|1\|1397\|16843011\|0
| 1.1.1.2 | 60 | 0 | 61 | www.facebook.com | 0 | www.facebook.com. | 3593 | - | www.facebook.com.\|1\|1\|63438\|16843010\|0
| 1.1.1.2 | 60 | 0 | 61 | www.facebook.com | 0 | star-mini.c10r.facebook.com. | 53 | 31.13.66.35 | www.facebook.com.\|1\|1\|63438\|16843010\|0
| 1.1.1.1 | 60 | 0 | 61 | www.facebook.com | 0 | www.facebook.com. | 3589 | - | www.facebook.com.\|1\|1\|32142\|16843009\|0
| 1.1.1.1 | 60 | 0 | 61 | www.facebook.com | 0 | star-mini.c10r.facebook.com. | 49 | 31.13.66.35 | www.facebook.com.\|1\|1\|32142\|16843009\|0

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

The output would, then, be a tab-delimited list of:
| Responding IP | IP header TTL | IP checksum | RTT (msec) | DNS qname | DNS RCODE | DNS domain name response | DNS TTL | IP address from response (if answer was an A record) | an internal cache key |
| --- | --- | --- |--- |--- |--- |--- |--- |--- |--- |
For example, the above might net the following output:
```
1.1.1.3	60	0	60	www.facebook.com	0	www.facebook.com.	3591	-	www.facebook.com.|1|1|1397|16843011|0
1.1.1.3	60	0	60	www.facebook.com	0	star-mini.c10r.facebook.com.	51	31.13.66.35	www.facebook.com.|1|1|1397|16843011|0
1.1.1.2	60	0	61	www.facebook.com	0	www.facebook.com.	3593	-	www.facebook.com.|1|1|63438|16843010|0
1.1.1.2	60	0	61	www.facebook.com	0	star-mini.c10r.facebook.com.	53	31.13.66.35	www.facebook.com.|1|1|63438|16843010|0
1.1.1.1	60	0	61	www.facebook.com	0	www.facebook.com.	3589	-	www.facebook.com.|1|1|32142|16843009|0
1.1.1.1	60	0	61	www.facebook.com	0	star-mini.c10r.facebook.com.	49	31.13.66.35	www.facebook.com.|1|1|32142|16843009|0
```

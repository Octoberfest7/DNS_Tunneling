# Intro
This Readme will serve as a blogpost.

Inspired by recent work I did involving Cobalt Strike DNS beacons, in conjunction with a mission statement to try and evade Microsoft Defender for Endpoint, I spent some time looking into how DNS might be used to transfer a payload to a target machine. I further wanted to challenge myself by trying to do so in a way that is possible even when powershell is in Constrained Language Mode. This research was targeted at more modern implementations of Windows (i.e. Win10+, Server 2019+) but as you see later it may be possible in lower versions.

# Background

## What is Constrained Language Mode?

Constrained Language Mode (CLM) is a restrictive language mode for Powershell which greatly reduces the capabilties and allowed functionality of Powershell.  As a short list, .NET, COM objects, and attacker favorites like (new-object net.webclient).downloadstring... are unavailable.  This link provides more information:

https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/

Organizations will put this policy in force for normal users as part of attack surface reduction rules.  It in effect just makes our lives harder as attackers.

## What do DNS records look like?

Most should be at least cursorily familiar with DNS from use of tools like Nslookup.  But at a basic level, the client sends a query and the DNS server returns an answer to that query.  There are several different kinds of DNS records: CNAME, A, AAAA, TXT, MX, and NS just to name a few.  Each of these records can store and return different information.  These records are configured in a Zonefile, which is served by a DNS server.

An example zonefile is shown here (https://help.dyn.com/how-to-format-a-zone-file/):

```
$ORIGIN example.com.
@                      3600 SOA   ns1.p30.dynect.net. (
                              zone-admin.dyndns.com.     ; address of responsible party
                              2016072701                 ; serial number
                              3600                       ; refresh period
                              600                        ; retry period
                              604800                     ; expire time
                              1800                     ) ; minimum ttl
                      86400 NS    ns1.p30.dynect.net.
                      86400 NS    ns2.p30.dynect.net.
                      86400 NS    ns3.p30.dynect.net.
                      86400 NS    ns4.p30.dynect.net.
                       3600 MX    10 mail.example.com.
                       3600 MX    20 vpn.example.com.
                       3600 MX    30 mail.example.com.
                         60 A     204.13.248.106
                       3600 TXT   "v=spf1 includespf.dynect.net ~all"
mail                  14400 A     204.13.248.106
vpn                      60 A     216.146.45.240
webapp                   60 A     216.146.46.10
webapp                   60 A     216.146.46.11
www                   43200 CNAME example.com.
```

If one were to query NS records for example.com, the query would return ns1.p30.dynect.net, ns2.p30.dynect.net, ns3.p30.dynect.net, and ns4.p30.dynect.net.

# What is DNS Tunneling?

DNS tunneling is a technique that has been around for a long time and used by a variety of attackers. At a basic level it involves using the DNS protocol as a means for data infiltration/exfiltration or as a C2 communications channel.  There are many blog posts you can reference for more information on this topic.

Because this is such a old and well known technique, many organizations have detection methods in place to try and prevent it. 

The DNS record type of choice for DNS tunneling is TXT records.  This is because TXT records can hold a lot more data than other records, and as I discovered during this research, they are also case-sensitive, something that the other records are not which can have an impact when we start talking about encoding.

Using TXT records as a means to smuggle data is often detected which led me to look at alternatives.

# Research

## Domain name registration 

Before we get started we have to talk briefly about setting up DNS records to point at an IP we control and will run a DNS server on.  As shown below I purchased a domain and set up DNS records that point the subdomain "dns" at the "ns1" subdomain which is assigned the public IP of the server.  

![image](https://user-images.githubusercontent.com/91164728/160316942-fc26fcbe-e217-42f8-a768-b420cd02d316.png)

This means that any queries made for "dns.edu....com" will be directed at "ns1.edu....com" which is assigned the IP 3..86.  On that IP we will set up a DNS server to serve our records. This will come around again later. 

## Finding a client side tool

My quest began with a simple google search for "powershell dns module" which returned this link:

https://docs.microsoft.com/en-us/powershell/module/dnsclient/?view=windowsserver2022-ps

Of particular interest was the Resolve-DnsName command.  It appears to be basically a powershell implementation of the well-known Nslookup.exe binary. Note that specific types of records can be requested:

![image](https://user-images.githubusercontent.com/91164728/160312929-cb297543-b9f3-4947-bdca-feef9062e1ef.png)

Ok, so we have a powershell module that is capable making dns queries and retreiving the answer.  Does it work in Constrained Language Mode? The answer is kind of.

As you can see here if I open a new powershell window, run Resolve-DnsName, put powershell into CLM (and test with the simple ::WriteLine call), and then run Resolve-DnsName again, it works without issue:

![image](https://user-images.githubusercontent.com/91164728/160314493-d027f4f1-7fee-412c-b6d5-a3d53198d9e5.png)

However if I open a new powershell window and immediately put it into CLM and then try to run Resolve-DnsName it fails:

![image](https://user-images.githubusercontent.com/91164728/160314638-3258609d-777d-4ae6-83e1-d04fcb6667f7.png)

It appears that if a module has been loaded before hand it is able to run once CLM is enforced, however CLM will prevent it from loading if it has not already done so. Thinking forward to a target environment where CLM is enforced for users by default (and with no knowledge if there are certain modules pre-loaded or if DnsClient is one of them), I chose at this point to leave Resolve-DnsName behind and turn back to good old Nslookup.exe.

![image](https://user-images.githubusercontent.com/91164728/160315058-87cd9ec6-4c65-4a5e-8700-f4d8c624d372.png)


Nslookup.exe is a staple of the IT toolkit and a very well known binary used for legitimate purposes.  The odds are in our favor that it will be allowed to execute even in environments where application whitelisting is a concern.

Nslookup will return much the same information as our Resolve-DnsName query, we will just have to manipulate it a little bit differently when the time comes.

## Turning an executable into DNS records?

Ok so we have a means by which to make DNS queries on the victim computer.  How can we provide our payload in a way that Nslookup could download?

Executables are of course binary files which means they aren't human readable.  This means we must find a way to transform the data into something that is human readable that we could stick into DNS records and that a tool like Nslookup could recover. There are ample encoding options available to us, but the major consideration is what can we decode on the victim box using only native windows tools and capabilities available in CLM?  Base64 is the obvious and often used answer.

Using Base64 we turn out executable into a giant human readable string which can then be broken up into many DNS records and recovered using Nslookup.  On the client side, the well known LOLBAS certutil.exe can be used to base64 decode the compiled DNS records back to binary format.  

This requires we talk a bit more about DNS record types.  Each record type stores certain information in a certain format. A records for example store and return an IPV4 address (111.111.111.111).  AAAA records return an IPV6 address, MX and NS records return domain names, and TXT records can return 255 character long strings.  As was previouly mentioned, due to the length of record and case-sensitivity, TXT records have been the obvious choice for attackers as fewer will be required and they are compatible with encoding like Base64.  

Lets see what this looks like.

On our Kali vm we can take our Executable and base64 it.  Note the use of the -w 0 switch which will remove all newlines so we are left with a single line of base64 text:

![image](https://user-images.githubusercontent.com/91164728/160316299-beda425a-a5d3-4467-9d43-6f5bb9bf2b07.png)

Looking at the file shows the base64:

![image](https://user-images.githubusercontent.com/91164728/160316342-7c2e1ca9-a2cf-4bcc-aee3-4670f4dd6191.png)

We now need to turn this base64'd file into DNS TXT records that will be served by our DNS server.  

There are a few things I learned during this that I will quickly summarize here before moving on:

  **1.** When multiple records return for a single DNS query, there is no guarantee that they will be returned in "order". This is critical for our purposes, as we need to reassemble a file from all of the TXT records and if they are out of order it won't work.
  
  **2.** Duplicate records aren't returned for a query.  For example, in our zonefile if we had 3 TXT records and 2 of them contained the same information, when we queried TXT records for that domain only 2 records would return as only the unique records are returned.  The not-in-order problem notwithstanding, if we had for example large sections of "AAAAA" (as we do in the Bas64'd payload) that we needed to fill multiple TXT records with, when we queried our domain for TXT records only one of the "A" filled TXT records would return even if there are several of them.
  
With these points in mind we must ensure that only a single TXT record is returned for each DNS query.  Enter subdomains.  Just as we registered "dns.edu...com" as a subdomain of "edu....com", we can provide records for further subdomains (e.g. 1.dns.edu....com).  We can this for as many TXT records as we need.  

Let look at our Base64'd payload:

![image](https://user-images.githubusercontent.com/91164728/160318505-d7b98905-e475-4ba2-94ae-492bc0bd3c63.png)

As previously mentioned we can stuff 255 characters into each TXT record.  Dividing 413696/255 yields 1,623 after rounding up.  That is a lot of TXT records (and by proxy a lot of subdomains). It is a start point howerver.

I wrote a Python3 script to ingest the Base64'd payload and create a zonefile:

```python3
#!/usr/bin/python3
def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))
    
myfile = open("/root/NRT/infil/comp.txt", "r")
data = myfile.read()
myfile.close()
zonefile = open("/root/NRT/infil/zonefile.com", "w")
contents = """$ORIGIN dns.educationcolony.com.
@                      3600 SOA   ns1.educationcolony.com. (
                              zone-admin.dyndns.com.     ; address of responsible party
                              2016072701                 ; serial number
                              60                       ; refresh period
                              600                        ; retry period
                              604800                     ; expire time
                              1800                     ) ; minimum ttl
                      86400 NS    ns1.educationcolony.com.
                         60 A     204.13.248.106
www                      60 A     204.13.248.106
"""
zonefile.write(contents)
i = 1
j = 0
for chunk in chunkstring(data, 255):
        zonefile.write(str(i) + "                         60 TXT   \"" + chunk.replace(" ","").strip("\n") + "\"\n")
        i = i + 1
zonefile.close()
print("value of 1 is: " + str(i))
```


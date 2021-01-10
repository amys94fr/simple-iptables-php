<?php
//Array of all log files you want to ban ips
// for centos $www_error_log_files = glob('/var/log/httpd/*');
$www_error_log_files = array('/var/log/apache2/access.log','/var/log/apache2/access.log.1','/var/log/apache2/error.log','/var/log/apache2/error.log.1');
$ips = array();
$banned_ips = array();

//ATTENTION here we reset all rules of iptables if you already have rules them will be erased
$cmd_reset = '/sbin/iptables -F';
exec($cmd_reset);

//Some ips you want to whitlist you should put your ip to not be block yourself
$allowed_ips = array(
	'127.0.0.1',
	//'your.allowed.ip.address',	
);
foreach($allowed_ips as $allowed_ip){
	$cmd_allowed_ip = "/sbin/iptables -A INPUT -s $allowed_ip -j ACCEPT";
	exec($cmd_allowed_ip);
}

//if you want to block some ports for exemple i block port 22 default ssh port
$cmd_block_port22 = '/sbin/iptables -A INPUT -p tcp --dport 22 -j DROP';
exec($cmd_block_port22);

//Loop of all log files
foreach($www_error_log_files as $www_error_log_file){
	print_r("FILE : $www_error_log_file\n");
	if(file_exists($www_error_log_file)){
		$www_error_log = file_get_contents($www_error_log_file);
		$www_error_log = explode("\n", $www_error_log);
		foreach($www_error_log as $line){
      //search ips from line
			if(preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $line, $ip)){
				$ip = $ip[0];
        //Pay attention we ban only ips that founded more than 1 time
				if(!in_array($ip, $ips)){ array_push($ips, $ip); }else{
					if(!in_array($ip, $banned_ips)){
						$cmd_block_ip = "/sbin/iptables -A INPUT -s $ip -j DROP";
						exec($cmd_block_ip);
						array_push($banned_ips, $ip);
					}
				}
			}
		}
	}
}

//if you not reset the rules like i do on the top that remove all duplicates rules
$cmd_remove_duplicate = '/sbin/iptables-save | uniq | /sbin/iptables-restore';
exec($cmd_remove_duplicate);

//if you want to make rules persistant
$cmd_save = '/sbin/iptables-save';
exec($cmd_save);

//print result
print_r("IPS : ".count($ips)."\n");
print_r("BANNED IPS : ".count($banned_ips)."\n");
?>

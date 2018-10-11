#!/bin/bash
# Based on https://www.drupal.org/node/244924
# Modified by Ahmed Shawky @lnxg33k

# Disable PHP insecure functions
disable_sys_funcs() {
	printf "\nDisabling PHP Dangerous/Insecure Functions ...\n"

	funcs_to_disable="apache_child_terminate, apache_setenv, define_syslog_variables, escapeshellarg, escapeshellcmd, eval, exec, fp, fput, ftp_connect, ftp_exec, ftp_get, ftp_login, ftp_nb_fput, ftp_put, ftp_raw, ftp_rawlist, highlight_file, ini_alter, ini_get_all, ini_restore, inject_code, mysql_pconnect, openlog, passthru, php_uname, phpAds_remoteInfo, phpAds_XmlRpc, phpAds_xmlrpcDecode, phpAds_xmlrpcEncode, popen, posix_getpwuid, posix_kill, posix_mkfifo, posix_setpgid, posix_setsid, posix_setuid, posix_setuid, posix_uname, proc_close, proc_get_status, proc_nice, proc_open, proc_terminate, shell_exec, syslog, system, xmlrpc_entity_decode"

	PHP_ini=$(find /etc/ -name php.ini 2>&1 | grep apache)

	if [[ $PHP_ini ]]; then
		PHP_ini_was_found=true;
		funcs_to_disable="$funcs_to_disable, phpinfo"
	else
		PHP_ini=$(php -r "phpinfo();" | grep -oE "\s+/.*?php.ini" | sed -e 's/^[ \t]*//')
		PHP_ini_was_found=true;
	fi

	if [ "$PHP_ini_was_found" = true ]; then
		for php_ini_path in $PHP_ini
		do
			printf "php.ini path was found => $php_ini_path\n"
			echo "; PHP security hardening by $(whoami) at $(date)" >>$php_ini_path
			system_has_disabled_funcs=$(grep -i -E "^disable_functions\s*=\s*" $php_ini_path | awk -F'=' '{ print $2 }' | sed -e 's/^[ \t]*//')
			if [[ $(echo $system_has_disabled_funcs | wc -c) -gt 1 ]]; then
				# printf "[!] Found disabled functions: $system_has_disabled_funcs\n"
				sed -i -e "/^disable_functions/ s/^[#|;]*/;/" $php_ini_path
				if [ "$system_has_disabled_funcs" != "$funcs_to_disable" ]; then
					echo "disable_functions=$(echo $funcs_to_disable), $system_has_disabled_funcs" >>$php_ini_path
				else
					echo "disable_functions=$(echo $funcs_to_disable)" >>$php_ini_path
				fi
			else
				sed -i -e "/^disable_functions/ s/^[#|;]*/;/" $php_ini_path
				echo "disable_functions=$(echo $funcs_to_disable)" >>$php_ini_path
			fi
		done
		printf "Successfully disabled: $funcs_to_disable\n"
		printf "\n--------------------------------------\n";
		printf "|[x] Please, reload the webserver... |";
		printf "\n--------------------------------------\n"
	else
		echo "Could not determine the php.ini file location, please report!"
		exit 1
	fi
}

# Help menu
print_help() {
	cat <<-HELP
This script is used to fix permissions of a Drupal installation and to disable PHP insecure functions
you need to provide the following arguments:

  1) Path to your Drupal installation.
  2) Username of the user that you want to give files/directories ownership.
  3) HTTPD group name (defaults to www-data for Apache).

Usage: (sudo) bash ${0##*/} --drupal_path=PATH --drupal_user=USER --httpd_group=GROUP
Example: (sudo) bash ${0##*/} --drupal_path=/usr/local/apache2/htdocs --drupal_user=john --httpd_group=www-data
HELP
	exit 0
}

if [ $(id -u) != 0 ]; then
	printf "***********************************************\n"
	printf "* Error: You must run this with sudo or root. *\n"
	printf "***********************************************\n"
	print_help
	exit 1
fi

drupal_path=${1%/}
drupal_user=${2}
httpd_group=${3}

# Parse Command Line Arguments
while [ "$#" -gt 0 ]; do
	case "$1" in
	--drupal_path=*)
		drupal_path="${1#*=}"
		;;
	--drupal_user=*)
		drupal_user="${1#*=}"
		;;
	--httpd_group=*)
		httpd_group="${1#*=}"
		;;
	--help) print_help ;;
	*)
		printf "************************************************************\n"
		printf "* Error: Invalid argument, run --help for valid arguments. *\n"
		printf "************************************************************\n"
		exit 1
		;;
	esac
	shift
done

if [ -z "${drupal_path}" ] || [ ! -d "${drupal_path}/sites" ] || [ ! -f "${drupal_path}/core/modules/system/system.module" ] && [ ! -f "${drupal_path}/modules/system/system.module" ]; then
	printf "**********************************************\n"
	printf "* Error: Please provide a valid Drupal path. *\n"
	printf "**********************************************\n"
	print_help
	exit 1
fi

if [ -z "${drupal_user}" ] || [[ $(id -un "${drupal_user}" 2>/dev/null) != "${drupal_user}" ]]; then
	printf "***************************************\n"
	printf "* Error: Please provide a valid user. *\n"
	printf "***************************************\n"
	print_help
	exit 1
fi

if [ -z "${httpd_group}" ] || [[ "$(grep -oE "^${httpd_group}:" /etc/group 2>/dev/null)" != "${httpd_group}:" ]]; then
	printf "****************************************\n"
	printf "* Error: Please provide a valid group. *\n"
	printf "****************************************\n"
	print_help
	exit 1
fi

if [ "${drupal_user}" == "${httpd_group}" ]; then
	printf "********************************************************\n"
	printf "* Error: The owner should be different than the group. *\n"
	printf "********************************************************\n"
	print_help
	exit 1
fi

cd $drupal_path
printf "Changing ownership of all contents of "${drupal_path}":\n user => "${drupal_user}" \t group => "${httpd_group}"\n"
chown -R ${drupal_user}:${httpd_group} .

printf "\nChanging permissions of all directories inside "${drupal_path}" to "rwxr-x---"...\n"
find . -type d -exec chmod u=rwx,g=rx,o= '{}' \;

printf "Changing permissions of all files inside "${drupal_path}" to "rw-r-----"...\n"
find . -type f -exec chmod u=rw,g=r,o= '{}' \;

printf "Changing permissions of "files" directories in "${drupal_path}/sites" to "rwxrwx---"...\n"
cd sites
find . -type d -name files -exec chmod ug=rwx,o= '{}' \;

printf "Changing permissions of all files inside all "files" directories in "${drupal_path}/sites" to "rw-rw----"...\n"
printf "Changing permissions of all directories inside all "files" directories in "${drupal_path}/sites" to "rwxrwx---"...\n"
for x in ./*/files; do
	find ${x} -type d -exec chmod ug=rwx,o= '{}' \;
	find ${x} -type f -exec chmod ug=rw,o= '{}' \;
done

printf "\nDisabling the PHP engine entirely in ${drupal_path}/sites/default/files...\n"
# incase we go shelled, overwrite the .htaccess
# if [ ! -f ${drupal_path}/sites/default/files/.htaccess ]; then
# printf ".htaccess files was not found in ${drupal_path}/sites/default/files/.htaccess !\n"
cat >./*/files/.htaccess <<EOF
# Turn off all options we don't need.
Options None
Options +FollowSymLinks

# Set the catch-all handler to prevent scripts from being executed.
SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006
<Files *>
# Override the handler again if we're run later in the evaluation list.
SetHandler Drupal_Security_Do_Not_Remove_See_SA_2013_003
</Files>

# If we know how to do it safely, disable the PHP engine entirely.
<IfModule mod_php5.c>
php_flag engine off
</IfModule>
EOF
# fi
printf "Changing the .htaccess file permission back to "----r-----"...\n"
chown ${drupal_user}:${httpd_group} ./*/files/.htaccess
chmod u=,g=r,o= ./*/files/.htaccess
echo "Done setting proper permissions on files and directories."

disable_sys_funcs

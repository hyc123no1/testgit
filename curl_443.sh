#!/bin/bash
#White list analysis script.
#powered by lance.
#Version 1.1

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/bin
dfile=$1
httpskey=$2
locationkey=$3
thread=$4
ipDns=$5

if [ ! -f $dfile ];then
	echo "$dfile does not exist."
	exit 1
fi

dos2unix ${dfile} >>/dev/null 2>&1
sed -i '/^$/d' ${dfile}
sed -i "s#^.*\:\/\/##g" ${dfile}
sed -i "s#\([^/]*\)\/.*#\1#g" ${dfile}
sed -i "s#\:.*##g" ${dfile}
sort -u ${dfile} -o ${dfile}
sed '=' ${dfile} |sed 'N;s/\n/ /g' > .${dfile}.temp
new_dfile=".${dfile}.temp"
	
#并发数验证
if [[ -z ${thread} ]];then
	thread=100
else
	if [[ `echo -e ${thread} | grep "\."` != "" ]];then
		ipDns="$thread"
		thread=100
	else
		echo -e ${thread} | egrep '^[1-9][0-9]{0,2}$' >> /dev/null
		[[ $? -ne 0 ]] && echo -e '\033[31mThe number of concurrent error, please enter "1 - 999"\033[0m' && exit 1
	fi
fi

#DNS验证
if [[ -z ${ipDns} ]];then
	nalicmd="nali-dig" && cmd="dig" && Parameter="-T4 -sS -P0 --system-dns -n -open -p T:80"
else
	echo -e  ${ipDns} | egrep '^([1-9][0-9]{0,2}\.){3}[1-9][0-9]{0,2}$'  >> /dev/null
	if [[ $? -eq 0 ]];then
		nalicmd="nali-dig @${ipDns}" && cmd="dig @${ipDns}" && Parameter="-T4 -sS -P0 --dns-servers ${ipDns} -n -open -p T:80"
	else
		echo -e "\033[31mDNS error.\033[0m" && exit 1
	fi
fi

#判断nmap是否安装
rpm -qi nmap >/dev/null 2>&1
if [ $? -ne 0 ];then
        echo -e "\033[31mERROR: Nmap is not installed.(yum install nmap -y)\033[0m"
        exit 1
fi

if [[ $locationkey -eq 1 ]];then
	rpm -qa| grep nali >> /dev/null 2>&1
	if [[ $? -eq 0 ]];then
		nali-update
	else
		echo "\033[31mERROR: nali is not installed.\033[0m"
		exit 1
	fi
fi

#判断网内外域名
function searchlocation {
		${nalicmd} $2 2>>/dev/null|sed -n '/ANSWER SECTION:/,/^$/p' | egrep "移动" >> /dev/null 2>&1
		[[ $? -eq 0 ]] && location="inner" || location="outer"
}

#判断80端口是否开启
function check_port_80 {
	nmap ${Parameter} $2 2>>/dev/null | grep "80/tcp open" >> /dev/null 2>&1
	[[ $? -eq 0 ]] && port_80="80_open" || port_80="80_close"
}

#判断https协议#
function check_https {
	curl -svo /dev/null  --connect-timeout 15 -m 15 "https://$2"  2>/dev/null
	case $? in
	0)
		https="https_open"
		;;
	28|51|60)
		curl -svo /dev/null  --connect-timeout 15 -m 15 "https://$2"  2>/dev/null
		[ $? -eq 0 ] && https="https_open" || https="https_close"
		;;
	*)
		https="https_close"
		;;
	esac
}

#检测别名https
function alias_check {
	j=0
	alias_https="cname_https_close"
	if [[ `${cmd} $2|egrep -w "CNAME"` != "" ]] ;then
		for a in `${cmd} $2 | awk '{if($4 == "CNAME" && $5 != "" ) print $5}'|sed 's/.$//g'`
		do
			check_https $j $a
			alias[$j]=$a 
			[[ "${https}" == "https_open" ]] && alias_https="cname_https_open" && break
			((j++))			
		done
		aliases=$(echo ${alias[@]} |sed 's/ /,/g')
	else
		aliases="none"
	fi
}

function main {
	[[ $locationkey -eq 1 ]] && searchlocation $domain || location=-1
	if [[ ${httpskey} -eq 1 ]];then
		if [[ $location == "inner" ]];then
			mdomain_https=-1 && alias_https=-1 && aliases=-1
		else
			check_https $domain
			mdomain_https="$https"
			[[ "$https" == "https_open" ]] && alias_https=-1 && aliases=-1 || alias_check $domain
		fi
	else
		mdomain_https=-1 && alias_https=-1 && aliases=-1
	fi
	check_port_80 $domain
	echo -e "${domain}\t${location}\t${port_80}\t${mdomain_https}\t${alias_https}\t${aliases}" | tee -a 443done_temp.txt
}

pipefile=/tmp/$$.fifo
mkfifo $pipefile
exec 5<>$pipefile
rm -rf $pipefile

for ((i=0;i<$thread;i++))
do
	echo
done>&5

while read domain
do
	read<&5
	(main $domain && echo>&5)&
done <$new_dfile
wait
exec 5>&-
sort -n 443done_temp.txt |sed "s#^[0-9]* ##" >443done.txt
rm -rf 443done_temp.txt
rm -rf ${new_dfile}
echo "#############################"
echo " See result in 443done.txt !!"
echo "#############################"

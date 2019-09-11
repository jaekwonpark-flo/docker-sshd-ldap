#!/bin/bash

DIALOG="dialog"
MENU_LIST=$(mktemp /tmp/menu.list.XXX)
SERVER_LIST=$(mktemp /tmp/server.XXX)
BASTION_SERVER_IP=$(grep BASTION_SERVER_IP /BASTION_SERVER | awk '{print $2}')
BASTION_SERVER_PORT=$(grep BASTION_SERVER_PORT /BASTION_SERVER | awk '{print $2}') 
BASTION_ID=$(grep BASTION_ID /BASTION_SERVER | awk '{print $2}')
REGION=$(grep REGION /BASTION_SERVER | awk '{print $2}')



userid=$(id | awk '{print $1}' | awk -F\( '{print $2}' | sed -e s/\)//g)
user_search=$(ldapsearch -h ldap -D "ADMIN_DN " -w ADMIN_DN_PASS -x -b "LDAP_BASE" "(&(gidNumber=*)(uid=$userid))" gidNumber | grep gidNumber: | awk '{print $2}')
group_name=$(ldapsearch -h ldap -D "ADMIN_DN " -w ADMIN_DN_PASS -x -b "ou=group,LDAP_BASE" "(&(gidNumber=$user_search))" cn | grep cn: | awk '{print $2}')

#ADMIN_DN="cn=admin,dc=example,dc=com"
#ADMIN_DN_PASS="admin_pass"
#LDAP_BASE="dc=example,dc=com"
#REGION="ap-northeast-2"
#user_search=$(ldapsearch -h localhost -D "$ADMIN_DN " -w $ADMIN_DN_PASS -x -b "$LDAP_BASE" "(&(gidNumber=*)(uid=$userid))" gidNumber | grep gidNumber: | awk '{print $2}')
#group_name=$(ldapsearch -h localhost -D "$ADMIN_DN " -w $ADMIN_DN_PASS -x -b "ou=group,$LDAP_BASE" "(&(gidNumber=$user_search))" cn | grep cn: | awk '{print $2}')


trap ctrl_c INT
trap ctrl_c SIGINT
trap ctrl_c SIGTERM

function ctrl_c() {
    logger -t [BASTION] -i -p authpriv.info catch the user Break
    exit
}


get_server_list () {
    if [[ $group_name == "admin" ]]; then
	aws ec2 describe-instances --query 'Reservations[*].Instances[*].{EAZ:Placement.AvailabilityZone,CInstance:PrivateIpAddress,Zssh:Tags[?Key==`ssh`]|[0].Value,AName:Tags[?Key==`Name`]|[0].Value,Buser:Tags[?Key==`ssh_user`]|[0].Value,Dinstanceid:InstanceId}' --output=text | grep -E "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" | awk  -F'\t' '{  cmd="echo "$3" | md5sum | fold -w 6"; cmd | getline x; close(cmd) ; print $1"-"x","$2","$3","$4","$5","$6}' >> $SERVER_LIST
    else
	aws ec2 describe-instances --query 'Reservations[*].Instances[*].{EAZ:Placement.AvailabilityZone,CInstance:PrivateIpAddress,Zssh:Tags[?Key==`ssh`]|[0].Value,AName:Tags[?Key==`Name`]|[0].Value,Buser:Tags[?Key==`ssh_user`]|[0].Value,Dinstanceid:InstanceId}' --output=text | grep -E "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" | grep -P '(^|\s)\K'$userid'(?=\s|$)' | awk  -F'\t' '{  cmd="echo "$3" | md5sum | fold -w 6"; cmd | getline x; close(cmd) ; print $1"-"x","$2","$3","$4","$5","$6}' >> $SERVER_LIST
    fi
}

function set_menu_list() {
    count=0
    for i in $(cat $SERVER_LIST | awk -F, '{print $3}'); do
        host_name=$(grep -w $i $SERVER_LIST | awk -F, '{print $1}' | sed "s/ /-/g" )
	
        if [ $(fping -t 50 $i | grep -c "alive") -eq 1 ]; then
            echo "$host_name Alive-[$(echo $i | awk -F. '{print $3"."$4}')]" >>$MENU_LIST
        else
            echo "$host_name Down-[$(echo $i | awk -F. '{print $3"."$4}')]" >>$MENU_LIST
        fi
        echo $count
	count=$(expr $count + $((($RANDOM % 3))))
        if [ $count -gt "98" ]; then
            count=99
        fi
    done
    if [[ $group_name = "admin" ]] && [[ -n "$BASTION_SERVER_IP" ]]; then
        echo "Bastion_server Alive" >>$MENU_LIST
    fi
    echo 100
    sleep 1
}

function exception_exit() {
    if [[ $? -ne 0 ]]; then
        rm -rf $MENU_LIST $SERVER_LIST
        exit
    fi
}


function print_connect_message() {
clear
echo "############################################"
echo -n "#"
echo "Connect to [$1]" | awk '
{ spaces = ('45' - length) / 2
  while (spaces-- > 0) printf (" ")
  print
}'
tput cup 1 43
echo "#"
echo "############################################"

}

get_server_list
set_menu_list | $DIALOG --backtitle "SSH CONNECTOR" --title "Server Status Check" --gauge "Find Alive Servers..." 6 80 0

server_alive=$(grep -c Alive $MENU_LIST)
server_down=$(grep -c Down $MENU_LIST)

if [ $(id -u) -ne 0 ]; then
    menu=$(cat $MENU_LIST)

    if [ ! -f /sshd_key/$userid ]; then
        while [ -z $ssh_pass ]; do
            ssh_pass=$($DIALOG --title "Password for sshkey file" --cancel-label "Exit" \
                --clear --insecure --passwordbox "Enter your ssh-key File  Password(not ssh id password)" 20 80 3>&1 1>&2 2>&3 3>&-)
            if [ $? -ne 0 ]; then
                clear
                echo "Exit from User"
                exit 0

            fi

            ssh_pass_verify=$($DIALOG --title "Password for sshkey file" --cancel-label "Exit" \
                --clear --insecure --passwordbox "Enter your ssh-key File  Password Again" 20 80 3>&1 1>&2 2>&3 3>&-)
            if [ $? -eq 0 ]; then
                if [ $ssh_pass == $ssh_pass_verify ] && [ $ssh_pass != "" ]; then
                    if ! ssh-keygen -f /sshd_key/$userid -P $ssh_pass -q; then
                        clear
                        echo "ssh-keygen Failed"
                        exit
                    fi
                else
                    if [ -z $ssh_pass ]; then
                        $DIALOG --title "Password for sshkey file" --clear --msgbox "Password is empty" 20 80
                    else
                        $DIALOG --title "Password for sshkey file" --clear --msgbox "Password doesn't match" 20 80
                    fi
                    unset ssh_pass
                fi
            else
                clear
                echo "Exit from User"
                exit 0

            fi
        done
    fi

    while [ -z $connect_host ]; do

        connect_host=$($DIALOG --backtitle "SSH CONNECTOR" --cancel-label "Exit" \
            --title "SSH Server List" --clear \
            --menu "[ID:$userid]    [GROUP:$group_name] \n $server_alive Server is Alive. $server_down Server is Down. \n [Select Server To Connect] " 30 80 22 $menu 3>&1 1>&2 2>&3 3>&-)

        if [ $? -eq 0 ]; then
            clear
            host_ip=$(grep "^$connect_host," $SERVER_LIST | awk -F, '{print $3}')
            user_id=$(grep "^$connect_host," $SERVER_LIST | awk -F, '{print $2}')
            instance_id=$(grep "^$connect_host," $SERVER_LIST | awk -F, '{print $4}')
            aws_az=$(grep "^$connect_host," $SERVER_LIST | awk -F, '{print $5}')
            if [ -z $user_id ]; then
                user_id=$userid
            fi
            if [ $connect_host != "Bastion_server" ]; then
                if [ $(fping -t 50 $host_ip | grep -c "alive") -eq 1 ]; then
                    print_connect_message $connect_host
                    logger -t [BASTION] -i -p authpriv.info connect to server $user_id@$host_ip
                    rm -rf $MENU_LIST $SERVER_LIST
		    aws ec2-instance-connect send-ssh-public-key --region $REGION --instance-id $instance_id  --availability-zone $aws_az --instance-os-user $user_id --ssh-public-key file:///sshd_key/$userid.pub
	       	    ssh -q -X -i /sshd_key/$userid -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $user_id@$host_ip && \
#		    mssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$instance_id
                    logger -t [BASTION] -i -p authpriv.info logout to server $user_id@$host_ip && \
                    exit
                else
                    rm -rf $MENU_LIST $SERVER_LIST
                    print_connect_message $connect_host
                    echo "############################################"
                    echo "#              Server is Down              #" 
                    echo "############################################"
		    echo $host_ip 
                    exit
                fi
                exception_exit
            else
                print_connect_message $connect_host
                logger -t [BASTION] -i -p authpriv.info connect to server $connect_host
                rm -rf $MENU_LIST $SERVER_LIST
		instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
		aws_az=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
		host_ip=$(curl -s  http://169.254.169.254/latest/meta-data/local-ipv4)
		user_id=$(echo $BASTION_ID)
		aws ec2-instance-connect send-ssh-public-key --region $REGION --instance-id $instance_id  --availability-zone $aws_az --instance-os-user $user_id --ssh-public-key file:///sshd_key/$userid.pub
	       	ssh -q -X -p $BASTION_SERVER_PORT -i /sshd_key/$userid -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $user_id@$host_ip && \
                #ssh -q -p $BASTION_SERVER_PORT -i /sshd_key/$userid -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $user_id@$BASTION_SERVER_IP && \
                logger -t [BASTION] -i -p authpriv.info logout to server $connect_host && \
                exit
                exception_exit
                echo "Have Nice Day?"
            fi
        else
            rm -rf $MENU_LIST $SERVER_LIST
            echo "Exit From User"
            exit 0
        fi
    done
fi

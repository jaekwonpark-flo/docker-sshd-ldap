#!/bin/bash

echo -e "BASE ${LDAP_BASE}\nURI ${LDAP_SERVER}" > /etc/nslcd.conf
echo -e "binddn $ADMIN_DN\nbindpw $ADMIN_DN_PASS" >> /etc/nslcd.conf

for item in passwd shadow group; do
    sed -i "s/^${item}:.*/${item}: ldap compat /g" /etc/nsswitch.conf
done

#sed -i "s/^Port 22/Port 2222/g" /etc/ssh/sshd_config
# clear motd 
sed -i "s/^PrintLastLog yes/PrintLastLog no/g" /etc/ssh/sshd_config
sed -i "s/^PermitRootLogin without-password/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/PasswordAuthentication yes/d" /etc/sshd_config

echo -e "\nForceCommand /usr/local/bin/record_ssh.sh" >> /etc/ssh/sshd_config

echo "" > /etc/motd
  
sed -i "s/ADMIN_DN /$ADMIN_DN/g" /etc/profile.d/userlist.sh
sed -i "s/ADMIN_DN_PASS/$ADMIN_DN_PASS/g" /etc/profile.d/userlist.sh
sed -i "s/LDAP_BASE/$LDAP_BASE/g" /etc/profile.d/userlist.sh

# ssh public key access config
if [[ $(grep -c "AuthorizedKeysCommand " /etc/ssh/sshd_config ) -eq 0 ]]; then   
  echo "AuthorizedKeysCommand /ldap_auth/ldap_auth.sh" >> /etc/ssh/sshd_config
fi
if [[ $(grep -c "AuthorizedKeysCommandUser " /etc/ssh/sshd_config ) -eq 0 ]]; then
  echo "AuthorizedKeysCommandUser nobody" >> /etc/ssh/sshd_config
fi
if [[ $(grep -c "AuthorizedKeysFile /dev/null" /etc/ssh/sshd_config ) -eq 0 ]]; then
  echo "AuthorizedKeysFile /dev/null" >> /etc/ssh/sshd_config
fi

if [[ $(grep -c "PasswordAuthentication no" /etc/ssh/sshd_config ) -eq 0 ]]; then
  echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
fi

echo "BASTION_SERVER_IP $BASTION_SERVER_IP" > /BASTION_SERVER
echo "BASTION_SERVER_PORT $BASTION_SERVER_PORT" >> /BASTION_SERVER
echo "BASTION_ID $BASTION_ID" >> /BASTION_SERVER
echo "REGION $REGION" >> /BASTION_SERVER


if /usr/sbin/nslcd ; then
  echo "run nslcd"
fi
if /usr/sbin/rsyslogd; then
  echo "run rsyslogd"
fi
if /usr/sbin/sshd -D ; then
  echo "run sshd"
fi

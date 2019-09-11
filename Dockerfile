FROM debian:jessie
MAINTAINER jaekwon park <jaekwon.park@sk.com>

# Configure apt
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libnss-ldapd libpam-ldapd openssh-server ldap-utils nscd dialog fping rsyslog  python3-pip  curl && \
    apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    pip3 install awscli --upgrade && mkdir -p /home/.aws/

ADD entrypoint.sh record_ssh.sh /usr/local/bin/
ADD ldap_auth.sh /ldap_auth/
ADD userlist.sh /etc/profile.d/
ADD protocols /etc/
ADD aws.config /home/.aws/config

RUN mkdir -p /var/run/sshd && chmod u+x /usr/local/bin/*.sh && chmod -R 755 /ldap_auth && chmod a+x /usr/local/bin/record_ssh.sh /etc/profile.d/userlist.sh

VOLUME /sshd_key

EXPOSE 22

CMD ["entrypoint.sh"]

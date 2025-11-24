FROM rockylinux:8
ENV container docker
RUN groupadd -r ncm-issuer && useradd -m -r -g ncm-issuer ncm-issuer
RUN yum -y update && yum -y install openssl traceroute iputils iproute net-tools wget curl nmap-ncat tcpdump bind-utils jq procps-ng lsof vim-minimal less strace && yum clean all
USER ncm-issuer

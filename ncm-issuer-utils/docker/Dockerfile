FROM rockylinux:8
ENV container=docker
RUN groupadd -r ncm-issuer && useradd -m -r -g ncm-issuer ncm-issuer
RUN yum -y update && yum -y install openssl traceroute iputils iproute net-tools wget curl nmap-ncat tcpdump bind-utils jq procps-ng lsof vim-minimal less strace libcap && yum clean all
# Grant file capabilities so the non-root sidecar user can run tcpdump and
# strace without needing root or CAP_NET_RAW/CAP_SYS_PTRACE in its ambient
# set. The matching container-level capabilities are added in the Helm chart
# via .Values.sidecar.securityContext.capabilities.add.
RUN setcap cap_net_raw,cap_net_admin+ep /usr/sbin/tcpdump && \
    setcap cap_sys_ptrace+ep /usr/bin/strace
USER ncm-issuer

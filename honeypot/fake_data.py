"""Static, fictional Ubuntu data used by the virtual environment.

Nothing in this module is collected from the machine running the honeypot.
The IP ranges used below are private or documentation-only ranges.
"""

from __future__ import annotations


SEED_DIRECTORIES = {
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/etc/apt",
    "/etc/ssh",
    "/home",
    "/home/ubuntu",
    "/opt",
    "/opt/backup",
    "/proc",
    "/root",
    "/root/backup",
    "/root/logs",
    "/root/scripts",
    "/root/ssh_keys",
    "/run",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/usr/bin",
    "/var",
    "/var/lib",
    "/var/lib/docker",
    "/var/log",
    "/var/www",
    "/var/www/html",
}


SEED_FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    ),
    "/etc/hostname": "server01\n",
    "/etc/hosts": (
        "127.0.0.1 localhost\n"
        "127.0.1.1 server01\n"
        "10.20.0.15 server01.internal server01\n"
    ),
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n'
        'NAME="Ubuntu"\n'
        'VERSION_ID="22.04"\n'
        'VERSION="22.04.5 LTS (Jammy Jellyfish)"\n'
        'VERSION_CODENAME=jammy\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
    ),
    "/etc/ssh/sshd_config": (
        "Include /etc/ssh/sshd_config.d/*.conf\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
        "UsePAM yes\n"
        "X11Forwarding yes\n"
    ),
    "/etc/apt/sources.list": (
        "deb http://archive.ubuntu.com/ubuntu jammy main restricted\n"
        "deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted\n"
        "deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n"
    ),
    "/root/.bash_history": (
        "apt update\n"
        "docker ps\n"
        "cd /var/log\n"
        "tail -n 30 auth.log\n"
        "systemctl status nginx\n"
    ),
    "/root/docker-compose.yml": (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:1.24\n"
        "    ports:\n"
        "      - \"80:80\"\n"
    ),
    "/root/test.py": 'print("backup complete")\n',
    "/root/scripts/backup.sh": (
        "#!/bin/bash\n"
        "tar -czf /opt/backup/site-latest.tar.gz /var/www/html\n"
    ),
    "/root/logs/app.log": (
        "2026-09-17 03:10:01 INFO application started\n"
        "2026-09-17 03:10:03 INFO connected to database\n"
        "2026-09-18 22:41:19 WARN request took 1240ms\n"
    ),
    "/root/ssh_keys/id_rsa.pub": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfFakeLabKeyOnly root@server01\n"
    ),
    "/home/ubuntu/.profile": (
        "if [ -d \"$HOME/bin\" ]; then\n"
        "    PATH=\"$HOME/bin:$PATH\"\n"
        "fi\n"
    ),
    "/var/log/auth.log": (
        "Sep 18 21:03:11 server01 sshd[2241]: Server listening on 0.0.0.0 port 22.\n"
        "Sep 18 22:09:42 server01 sshd[3048]: Accepted password for root from 10.20.0.8 port 51822 ssh2\n"
        "Sep 18 22:09:42 server01 sshd[3048]: pam_unix(sshd:session): session opened for user root(uid=0)\n"
    ),
    "/var/log/syslog": (
        "Sep 18 22:00:01 server01 systemd[1]: Started Daily apt download activities.\n"
        "Sep 18 22:17:01 server01 CRON[2881]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
    ),
    "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
    "/opt/backup/README.txt": "Nightly backups are retained for seven days.\n",
}


FAKE_PROCESSES = (
    ("root", "1", "0.0", "0.1", "168020", "11844", "?", "Ss", "Sep18", "0:04", "/sbin/init"),
    ("root", "234", "0.0", "0.1", "15424", "9548", "?", "Ss", "Sep18", "0:01", "/usr/sbin/sshd -D"),
    ("root", "567", "0.2", "1.4", "1842636", "118212", "?", "Ssl", "Sep18", "2:41", "/usr/bin/dockerd -H fd://"),
    ("www-data", "900", "0.0", "0.1", "55240", "6820", "?", "S", "Sep18", "0:00", "nginx: worker process"),
    ("root", "1182", "0.0", "0.0", "15420", "6120", "?", "Ss", "00:03", "0:00", "sshd: root@pts/0"),
    ("root", "1197", "0.0", "0.0", "10068", "3864", "pts/0", "R+", "00:04", "0:00", "ps aux"),
)


FAKE_INTERFACES = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:9a:31:7c brd ff:ff:ff:ff:ff:ff
    altname enp1s0
    inet 10.20.0.15/24 brd 10.20.0.255 scope global dynamic eth0
       valid_lft 82463sec preferred_lft 82463sec
    inet6 fe80::5054:ff:fe9a:317c/64 scope link
       valid_lft forever preferred_lft forever"""


FAKE_CONNECTIONS = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0      127.0.0.53%lo:53     0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53     0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22     0.0.0.0:*
tcp   LISTEN 0      511          0.0.0.0:80     0.0.0.0:*
tcp   ESTAB  0      0         10.20.0.15:22    10.20.0.8:51822"""


FAKE_DOCKER_PS = """CONTAINER ID   IMAGE        COMMAND                  CREATED      STATUS        PORTS                               NAMES
8c30a1cf91e2   nginx:1.24   \"/docker-entrypoint.…\"   12 days ago  Up 12 days    0.0.0.0:80->80/tcp, :::80->80/tcp   web-nginx-1
2e771d4bb180   redis:7      \"docker-entrypoint.s…\"   12 days ago  Up 12 days    6379/tcp                            web-redis-1"""


DEFAULT_SERVICES = {
    "ssh": "active",
    "sshd": "active",
    "nginx": "active",
    "docker": "active",
    "cron": "active",
    "redis-server": "active",
    "ufw": "inactive",
}


DEFAULT_PACKAGES = {
    "bash",
    "ca-certificates",
    "coreutils",
    "curl",
    "docker.io",
    "git",
    "nginx",
    "openssh-server",
    "python3",
    "wget",
}

FROM kalilinux/kali-linux-docker
RUN apt clean all && apt update && apt upgrade -y
RUN apt install -y aircrack-ng pciutils
RUN apt autoremove -y && apt clean all

# How to Build:

Within anp_netskeleton-master

 ```bash
 cmake . 
 make 
 sudo make install  
 ```

 DNS Stub resolver must also be disabled. [Here is a guide on how](https://askubuntu.com/questions/907246/how-to-disable-systemd-resolved-in-ubuntu/907249#907249)


 # How to use ANP
 
After every reboot, the following scripts must be run. Replace ’wlp1s0’ with the NIC
the host uses that has access to the outside

```bash
 cd bin
 sudo ./sh-make-tun-dev.sh 
 sudo ./sh-disable-ipv6.sh 
 sudo ./sh-setup-fwd.sh wlp1s0
 ```

ANP can be used with by running a similar command as bellow. Replace ’wget’ and its
arguments with the application you want to run and its arguments.

```bash
 sudo ./sh-hack-anp.sh wget https://vu.nl/nl
 ```
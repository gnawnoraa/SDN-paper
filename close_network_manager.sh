sudo service network-manager stop
# sudo ovs-vsctl set-manager ptcp:6632
sudo ifconfig eth0 up
sudo dhclient eth0

# Automate this, because today this just removes statics ports!
ovs-vsctl -- destroy QoS s1-eth1 -- clear Port s1-eth1 qos -- clear Port s1-eth1 qos

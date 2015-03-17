ovs-vsctl -- set Bridge s1 mirrors=@m \
              -- --id=@s1-eth1 get Port s1-eth1 \
              -- --id=@s1-eth2 get Port s1-eth2 \
              -- --id=@s1-eth3 get Port s1-eth3 \
              --   --id=@m    create    Mirror    name=mymirror    select-dst-port=@s1-eth1,@s1-eth2 select-src-port=@s1-eth1,@s1-eth2 output-port=@s1-eth3

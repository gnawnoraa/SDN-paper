#!/bin/bash
MTUVALUE=1516
ifconfig s1-eth1 mtu ${MTUVALUE}
ifconfig s1-eth2 mtu ${MTUVALUE}
ifconfig s1-eth3 mtu ${MTUVALUE}
ifconfig s1-eth4 mtu ${MTUVALUE}
ifconfig s1-eth5 mtu ${MTUVALUE}
ifconfig s1-eth6 mtu ${MTUVALUE}

ifconfig s2-eth1 mtu ${MTUVALUE}
ifconfig s2-eth2 mtu ${MTUVALUE}
ifconfig s2-eth3 mtu ${MTUVALUE}

ifconfig s3-eth1 mtu ${MTUVALUE}
ifconfig s3-eth2 mtu ${MTUVALUE}
ifconfig s3-eth3 mtu ${MTUVALUE}
ifconfig s3-eth4 mtu ${MTUVALUE}
ifconfig s3-eth5 mtu ${MTUVALUE}
ifconfig s3-eth6 mtu ${MTUVALUE}

ifconfig s4-eth1 mtu ${MTUVALUE}
ifconfig s4-eth2 mtu ${MTUVALUE}
ifconfig s4-eth3 mtu ${MTUVALUE}

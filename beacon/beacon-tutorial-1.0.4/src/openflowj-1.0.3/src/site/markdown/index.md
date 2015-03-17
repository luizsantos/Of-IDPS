# Introduction

Welcome to the homepage for OpenFlowJ, a Java bindings library for the [OpenFlow protocol](https://www.opennetworking.org/sdn-resources/onf-specifications/openflow).

OpenFlowJ currently supports all aspects of version 1.0 of the OpenFlow protocol.  It contains an object oriented representation of all OpenFlow messages, and code to serialize/deserialize these objects to/from [ByteBuffers](http://docs.oracle.com/javase/6/docs/api/java/nio/ByteBuffer.html).

# Where is it used

OpenFlowJ has been used extensively by Java-based Software Defined Networking controllers.  Here is a non-exhaustive list of known projects using it:

* [Beacon] (http://www.beaconcontroller.net/)
* [Big Network Controller] (http://www.bigswitch.com/products/SDN-Controller)
* [Floodlight] (http://www.projectfloodlight.org/floodlight/)
* [Open Daylight] (http://www.opendaylight.org/)

# History

OpenFlowJ was originally created by David Erickson with contributions from Rob Sherwood in February 2010.
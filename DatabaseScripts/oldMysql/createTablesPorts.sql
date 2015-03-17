create table ports(
 switchNumber int not null,
 portNumber int not null,
 collisions long,
 receiveBytes long,
 receiveCRCErrors long,
 receiveDropped long,
 receiveErrors long,
 receiveFrameErrors  long,
 receiveOverrunErrors  long,
 receivePackets  long,
 transmitBytes  long,
 transmitDropped  long,
 transmitErrors  long,
 transmitPackets  long,
 tempo long
 );

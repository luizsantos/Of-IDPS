create table alertsOpenFlow(
                tempo timestamp not null,
                priority int,
                alertDescription varchar(25) not null,
                networkSource int not null,
                networkDestination int not null,
                networkProtocol int not null,
                transportSource int not null,
                transportDestination int not null,
                PRIMARY KEY (tempo, alertDescription, networkSource, networkDestination, networkProtocol, transportSource, transportDestination)
 );

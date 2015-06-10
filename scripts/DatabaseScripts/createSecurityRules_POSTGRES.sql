create table securityRules(
		memory int,
                priority varchar(10),
                alertDescription varchar(25) not null,
                networkSource varchar(16) not null,
                networkDestination varchar(16) not null,
                networkProtocol varchar(4) not null,
                transportSource varchar(6) not null,
                transportDestination varchar(6) not null,
                supportApriori int not null,
                life int not null,
                averagePacketsMatchInOfControllerPerHop int not null,
                totalPacketsMatchInOfController int not null,
                averageOfTotalPacketsMatchInOfControllerPerSeconds int not null
 );
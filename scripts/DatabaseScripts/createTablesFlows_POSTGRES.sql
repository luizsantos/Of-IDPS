create table flows(
		swID bigint not null,
                tempo timestamp,
                byteCount bigint,
                cookie bigint,
                durationNanoseconds int,
                durationSeconds int,
                hardTimeout int,
                idleTimeout int,
                length int,
                packetCount bigint,
                priority int,
                tableId int,
                dataLayerDestination bytea,
                dataLayerSource bytea,
                dataLayerType int,
                dataLayerVirtualLan int,
                dataLayerVirtualLanPriorityCodePoint int,
                inputPort int,
                networkDestination int,
                networkProtocol int,
                networkSource int,
                networkTypeOfService int,
                transportDestination int,
                transportSource int, 
                wildcards int,
                flowType int
 );

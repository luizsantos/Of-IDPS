create table alertSnortComments(
		sig_sid int not null,
		useful int not null,
		summary_text text not null,
		impact text,
		detailedInformation text,
		affectedSystems text,
		attackScenarios text,
		easeOfAttack text,
		falsePositives text,
		falseNegatives text,
		correctiveAction text,
		contributors text,
		additionalReferences text,
                PRIMARY KEY (sig_sid)
 );
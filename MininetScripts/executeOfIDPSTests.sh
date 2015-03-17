#!/bin/bash
#./executeOfIDPSTests numberOfExecutions timeBetween execution
#ex:
# ./executeOfIDPSTests 5 10 - to execute 5 tests and waiting 10 seconds between each test execution.

for((i=1; i<=$1; i++))
do
        echo "================= Running Test $i==============="
        time /home/mininet/executaTeste.sh
        echo "Waiting $2 seconds for the next test!"
        sleep $2
done



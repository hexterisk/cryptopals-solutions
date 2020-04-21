#!/bin/bash

suffix=".py"
for i in 0{1..6}
do
	prefix="S"$i
	for j in {1..8}
	do
		let count=($i-1)*8+$j
		infix=`printf "C%02d\n" $count`
		touch $prefix$infix$suffix
	done
done

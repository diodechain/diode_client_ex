#!/bin/bash

for host in us1 us2 eu1 eu2 as1 as2; do
  url=${host}.prenet.diode.io
  echo $url
  SEED_LIST=$url $*
done

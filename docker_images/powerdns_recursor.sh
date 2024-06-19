#!/bin/bash
pdns_recursor --config-dir=/etc/powerdns --daemon=no &> /var/cache/powerdns/powerdns.log

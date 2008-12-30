
#
# Copyright (c) 2008 Rainer Clasen
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms described in the file LICENSE included in this
# distribution.
#

package Nspamper;

# TODO: pod

use strict;
use warnings;
use Net::DNS;
use Sys::Syslog;

sub get_domdat {
	my( $fqdn ) = @_;

	my( $dom ) = ( $fqdn =~ /\.(.*)/ );
	return ( $dom, &get_nameserver( $dom ));
}

# find nameserver responsible for a domain
sub get_nameserver {
	my( $domain ) = @_;

	my $res = new Net::DNS::Resolver;
	my $query = $res->query( $domain, "SOA" );
	if( ! $query ){
		syslog( "notice", "failed to get NS for $domain: ".
			$res->errorstring );
		return;
	}

	my $rr = ($query->answer)[0];
	if( $rr->type ne "SOA" ){
		syslog( "notice", "failed to get NS for $domain: ".
			"got non-SOA record");
		return;
	}

	my $master = $rr->mname;

	$query = $res->query( $master, "A" );
	if( ! $query ){
		syslog( "notice", "failed to get NS IP for $master: ".
			$res->errorstring );
		return;
	}
	
	$rr = ($query->answer)[0];
	if( $rr->type ne "A" ){
		syslog( "notice", "failed to get NS IP for $master: ".
			"got no A record");
		return;
	}

	return $rr->address;
}



# get current IP for a name from responsible server
sub get_ip {
	my( $ns, $name ) = @_;

	my $res = new Net::DNS::Resolver;
	$res->nameservers($ns);
	my $query = $res->query( $name, "A" );
	if( ! $query ){
		syslog( "notice", "failed to get current IP: ".
			$res->errorstring );
		return;
	}

	my $rr = ($query->answer)[0];
	if( $rr->type ne "A" ){
		syslog( "notice", "failed to get current IP: ".
			"got no A record" );
		return;
	}

	return $rr->address;
}

# update IP on server
sub set_ip {
	my( $ns, $dom, $key, $name, $ip ) = @_;

	syslog( "debug", "updating $name=$ip");

	my $upd = Net::DNS::Update->new( $dom );
	$upd->push( "update", rr_del("$name A"));
	$upd->push( "update", rr_add("$name 1 A $ip"));
	$upd->sign_tsig( $name, $key );

	my $res = Net::DNS::Resolver->new;
	$res->nameservers( $ns );
	my $rep = $res->send( $upd );
	if( defined $rep ){
		if( $rep->header->rcode ne "NOERROR" ){
			syslog( "notice", "failed to update $name: ".
				$rep->header->rcode );
			return;
		}
	} else {
		syslog( "notice", "failed to update $name: ".
			$res->errorstring );
		return;
	}

	return 1;
}

1;

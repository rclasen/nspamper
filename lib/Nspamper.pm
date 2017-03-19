package Nspamper;
use strict;
use warnings;
use Carp;
use Net::DNS;
use NetAddr::IP;

our $VERSION = 0.02;

# TODO: add / allow more verbose progress / error reporting

sub new {
	my( $proto ) = @_;

	bless {
		resolver	=> Net::DNS::Resolver->new,
		domain	=> {
			# name => [ $nsresolver, ... ]
		},
		ns	=> {
			# name => $resolver,
		},
	}, ref $proto || $proto;
}

sub ip_get {
	my( $self, $name, $resolver ) = @_;

	my @ip;

	if( my $r = $resolver->query( $name, 'A' ) ){
		foreach my $rr ( $r->answer ){
			push @ip, $rr->address
				if $rr->type eq 'A';
		}
	}

	if( my $r = $resolver->query( $name, 'AAAA' ) ){
		foreach my $rr ( $r->answer ){
			push @ip, $rr->address
				if $rr->type eq 'AAAA';
		}
	}

	@ip or return;

	return \@ip;
}

sub ns_get {
	my( $self, $ns ) = @_;

	my $ips = $self->ip_get( $ns, $self->{resolver} )
		or return;

	return Net::DNS::Resolver->new(
		nameservers	=> $ips,
	);
}

sub ns {
	my( $self, $ns ) = @_;

	$ns = lc $ns;

	$self->{ns}{$ns}
		||= $self->ns_get( $ns );
}

sub domain_get {
	my( $self, $domain ) = @_;

	my @resolver;

	if( my $r = $self->{resolver}->query( $domain, 'SOA' ) ){
		foreach my $rr ( $r->answer ){
			$rr->type eq 'SOA'
				or next;

			my $ns = $self->ns( $rr->mname )
				or next;

			push @resolver, $ns;
		}
		# TODO: only lookup A/AAAA if they're not in $rr->additional
	}

	# TODO: secondary NS... if they don't get xfer from primary

	# report failure if no resolver was found
	@resolver or return;

	return \@resolver;
}

sub domain {
	my( $self, $domain ) = @_;

	$domain = lc $domain;

	$self->{domain}{$domain}
		||= $self->domain_get( $domain );
}

sub compare_rr {
	my( $self, $resolver, $domain, $host, $t, $want ) = @_;

	my $na;
	if( ! defined $want ){
		# ok

	} elsif( $t eq 'A' or $t eq 'AAAA' ){
		$na = eval { NetAddr::IP->new($want) }
			or return;
	}

	my $name = "$host.$domain";

	my( $ok, $bad );

	if( my $r = $resolver->query( $name, $t ) ){

		foreach my $rr ( $r->answer ){
			$rr->type eq $t
				or next;

			if( ! defined $want ){
				++$bad;

			} elsif( $t eq 'A' or $t eq 'AAAA' ){
				my $wa = eval { NetAddr::IP->new( $rr->address ) };

				if( ! $wa ){
					++$bad;

				} elsif( $na eq $wa ){
					++$ok;

				} else {
					++$bad;
				}
			}

			# TODO: other rrtypes
		}

	} else {
		++$bad;
	}

	return if $ok && ! $bad;

	my $update = Net::DNS::Update->new( $domain );
	$update->push( "update", rr_del("$name $t"));
	$update->push( "update", rr_add("$name 1 $t $want"))
		if defined $want;

	return {
		resolver	=> $resolver,
		update		=> $update,
		name		=> $name,
		type		=> $t,
		want		=> $want,
	};
}

sub compare {
	my( $self, $domain, $host, $want ) = @_;

	my $resolver = $self->domain( $domain )
		or return;

	my @changes;

	foreach my $res ( @$resolver ){
		foreach my $t ( keys %$want ){
			if( my $c = $self->compare_rr( $res, $domain, $host, $t, $want->{$t} ) ){
				push @changes, $c;
			}
		}
	}

	return \@changes;
}

sub update {
	my( $self, $key, $changes ) = @_;

	ref $changes eq 'ARRAY'
		or croak "bad changes argument";

	my $error;

	foreach my $c ( @$changes ){
		my $resolver = $c->{resolver};

		$c->{update}->sign_tsig( $c->{name}, $key );
		if( my $r = $resolver->send( $c->{update} ) ){
			if( $r->header->rcode ne 'NOERROR' ){
				$c->{error} = $r->header->rcode;
				++$error;
			}

		} else {
			$c->{error} = $resolver->errorstring;
			++$error;
		}
	}

	return !$error;
}

1;



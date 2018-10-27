#!/usr/bin env perl

use strict;
use warnings;

use IO::All;
use Mojo::IOLoop;
use Mojo::Server::Prefork;
use Mojo::URL;
use Mojo::UserAgent;
use Web::MIME::Sniffer;
use Web::MIME::Type;

my $DEBUG = 0;

my %blocklist = map { chomp($_); $_ => 1 } io('./blocklist.txt')->slurp;
my $prefork = Mojo::Server::Prefork->new(listen => [ 'http://10.1.0.193:5000' ]);
$prefork->accepts(0);
$prefork->workers(32);
my $ua = Mojo::UserAgent->new(max_response_size => 10*1024*1024);
$ua->ioloop($prefork->ioloop);
warn $prefork->max_requests;
$prefork->on(
    error => sub {
        my ($prefork, $err) = @_;
        warn 'Request failed: ' . $err->[1];
        fail_request($err->[0]);
    }
);

$prefork->unsubscribe('request')->on(
    request => sub {
        my ($prefork, $tx) = @_;

        if ($tx->req->url->path !~ /^\/iu/) {
            $prefork->emit('error', [ $tx, 'bad path' ]);
            return;
        }

        my ($u_param) = $tx->req->url->query->param('u');
        if (!$u_param) {
            $prefork->emit('error', [ $tx, 'invalid upstream' ]);
            return;
        }

        my ($upstream) = Mojo::URL->new($u_param);

        if  (!$upstream ||
                 ($upstream->scheme ne 'http' && $upstream->scheme ne 'https') ||
                 ($upstream->port && $upstream->port != 80 && $upstream->port != 443) ||
                 exists $blocklist{$upstream->to_string}) {
            $prefork->emit('error', [ $tx, 'bad request']);
            return;
        }

        $DEBUG && warn 'processing request for ' . $upstream->to_string;

        $ua->get($upstream->to_string => sub {
            my ($ua, $itx) = @_;
            $DEBUG && warn 'result size: ' . $itx->res->body_size;

            if (!is_valid_file($itx)) {
                $prefork->emit('error', [ $tx, 'bad mime type' ]);
                return;
            }

            $tx->res($itx->res);
            $tx->res->build_body;
            $tx->resume;
        });
    }
);
$prefork->run;

sub is_valid_file {
    my ($tx) = @_;

    my $content_type = $tx->res->headers->content_type;
    my $mime = $content_type ? Web::MIME::Type->parse_web_mime_type($content_type) : undef;
    my $sniffer = Web::MIME::Sniffer->new_from_context('image');
    # Per https://mimesniff.spec.whatwg.org algo.
    my $detected_mime = $sniffer->detect($mime, (substr $tx->res->body, 0, 1445));
    $DEBUG && warn 'detected mime: ' . $detected_mime->mime_type_portion;

    return 0 unless $detected_mime->mime_type_portion =~ /^image\//;
    return 1;
}

sub fail_request {
    my ($tx) = @_;

    $tx->res->code(404);
    $tx->res->headers->content_type('text/plain');
    $tx->res->body('request failed');
    $tx->resume;
}

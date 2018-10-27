package Web::MIME::Type::Parser;
use strict;
use warnings;
our $VERSION = '2.0';
use Web::MIME::Type;

sub new ($) {
  return bless {}, $_[0];
} # new

sub onerror ($;$) {
  if (@_ > 1) {
    $_[0]->{onerror} = $_[1];
  }
  return $_[0]->{onerror} ||= sub {
    my %opt = @_;
    my @msg = ($opt{type});
    push @msg, $opt{value} if defined $opt{value};
    push @msg, ' at position ' . $opt{index};
    warn join '; ', @msg, "\n";
  };
} # onerror

my $HTTPToken = qr/[\x21\x23-\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]+/;

sub parse_string ($$) {
  my ($self, $value) = @_;
  my $onerror = $self->onerror;

  ## <https://mimesniff.spec.whatwg.org/#supplied-mime-type-detection-algorithm>
  my $apache_bug;
  if ($value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E" or
      $value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E\x3B\x20\x63\x68\x61\x72\x73\x65\x74\x3D\x49\x53\x4F\x2D\x38\x38\x35\x39\x2D\x31" or
      $value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E\x3B\x20\x63\x68\x61\x72\x73\x65\x74\x3D\x69\x73\x6F\x2D\x38\x38\x35\x39\x2D\x31" or
      $value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E\x3B\x20\x63\x68\x61\x72\x73\x65\x74\x3D\x55\x54\x46\x2D\x38") {
    $apache_bug = 1;
  }

  $value =~ s/[\x09\x0A\x0C\x0D\x20]+\z//;
  pos ($value) = 0;
  $value =~ /\A[\x09\x0A\x0C\x0D\x20]+/gc;

  my $type;
  if ($value =~ /\G($HTTPToken)/ogc) {
    $type = $1;
  } else {
    my $pos = pos $value;
    $value =~ m{\G([^/]*)}gc;
    $onerror->(type => 'MIME type:bad type',
               level => 'm',
               index => $pos,
               value => $1);
    return undef;
  }

  unless ($value =~ m[\G/]gc) {
    $onerror->(type => 'MIME type:no /',
               level => 'm',
               index => pos $value);
    return undef;
  }

  my $subtype;
  if ($value =~ /\G($HTTPToken)/ogc) {
    $subtype = $1;
  } else {
    my $pos = pos $value;
    $value =~ m{\G([^/]*)}gc;
    $onerror->(type => 'MIME type:bad subtype',
               level => 'm',
               index => $pos,
               value => $1);
    return undef;
  }

  $value =~ /\G[\x09\x0A\x0C\x0D\x20]+/ogc;

  my $mt = Web::MIME::Type->new_from_type_and_subtype ($type, $subtype);
  $mt->{apache_bug} = 1 if $apache_bug;

  while ($value =~ /\G;/gc) {
    $value =~ /\G[\x09\x0A\x0C\x0D\x20]+/ogc;
    
    my $attr = '';
    my $attr_pos = pos $value;
    if ($value =~ /\G([^=;]*)/ogc) {
      $attr = $1;
    }

    unless ($value =~ /\G=/gc) {
      if (not $attr =~ /\A$HTTPToken\z/o) {
        $onerror->(type => 'params:bad name',
                   level => 'm',
                   index => $attr_pos,
                   value => $attr);
      } else {
        $onerror->(type => 'params:no =',
                   level => 'm',
                   index => pos $value);
      }
      next;
    }

    $attr =~ tr/A-Z/a-z/; ## ASCII lowercase
    my $v;
    my $v_pos = pos $value;
    my $v_bad;
    if ($value =~ /\G"/gc) {
      $value =~ /\G((?>[^"\\]+|\\.|\\\z)*)/gcs;
      $v = $1;
      $v =~ s/\\(.)/$1/gs;
      unless ($value =~ /\G\x22/gc) {
        $onerror->(type => 'params:no close quote',
                   level => 'm',
                   index => pos $value);
      }
      if ($value =~ /\G[^;]+/gc) {
        $onerror->(type => 'params:garbage after quoted-string',
                   level => 'm',
                   index => pos $value);
      }
    } else {
      $value =~ /\G([^;]*)/gc;
      $v = $1;
      $v =~ s/[\x09\x0A\x0C\x0D\x20]+\z//g;
      if (not $v =~ /\A$HTTPToken\z/o) {
        $onerror->(type => 'params:bad value token',
                   level => 'm',
                   index => $v_pos,
                   value => $v);
        $v_bad = 1;
      }
    }

    if (not $attr =~ /\A$HTTPToken\z/o) {
      $onerror->(type => 'params:bad name',
                 level => 'm',
                 index => $attr_pos,
                 value => $attr);
      next;
    }

    # HTTP quoted-string token code point
    unless ($v =~ /\A[\x09\x20-~\x80-\xFF]+\z/) {
      $onerror->(type => 'params:bad value',
                 level => 'm',
                 index => $v_pos,
                 value => $v)
          unless $v_bad;
      next;
    }

    my $current = $mt->param ($attr);
    if (defined $current) {
      $onerror->(type => 'params:duplicate name',
                 level => 'm',
                 value => $attr,
                 index => $attr_pos);
      next;
    } else {
      $mt->param ($attr => $v);
    }
  } # params

  if (pos $value < length $value) {
    $onerror->(type => 'MIME type:bad char after subtype',
               level => 'm',
               index => pos $value);
    return undef;
  }

  return $mt;
} # parse_string

1;

=head1 LICENSE

Copyright 2007-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

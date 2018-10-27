package Web::MIME::Type;
use strict;
use warnings;
our $VERSION = '4.0';

## ------ Instantiation ------

## NOTE: RFC 2046 sucks, it is a poorly written specification such that
## what we should do is not entirely clear and it does define almost nothing
## from the today's viewpoint...  Suprisingly, it's even worse than
## RFC 1521, the previous version of that specification, which does
## contain BNF rules for parameter values at least.

my $ErrorLevels = {
  must => 'm',
  warn => 'w',
  info => 'i',
  uncertain => 'u',

  mime_must => 'm', # lowercase "must"
  mime_fact => 'm',
  mime_strongly_discouraged => 'w',
  mime_discouraged => 'w',

  http_fact => 'm',
}; # $ErrorLevels

sub new_from_type_and_subtype ($$$) {
  my $self = bless {param_names => []}, shift;
  $self->{type} = ''.$_[0];
  $self->{type} =~ tr/A-Z/a-z/;
  $self->{subtype} = ''.$_[1];
  $self->{subtype} =~ tr/A-Z/a-z/;
  return $self;
} # new_from_type_and_subtype

## Deprecated
sub parse_web_mime_type ($$;$) {
  my ($class, $value, $onerror) = @_;
  require Web::MIME::Type::Parser;
  my $parser = Web::MIME::Type::Parser->new;
  $parser->onerror ($onerror);
  return $parser->parse_string ($value); # or undef
} # parse_web_mime_type

## ------ Accessors ------

sub type ($;$) {
  my $self = shift;
  if (@_) {
    $self->{type} = ''.$_[0];
    $self->{type} =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
  }

  return $self->{type};
} # top_level_type

sub subtype ($;$) {
  my $self = shift;
  if (@_) {
    $self->{subtype} = ''.$_[0];
    $self->{subtype} =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
  }

  return $self->{subtype};
} # subtype

sub param ($$;$) {
  my $self = shift;
  my $n = ''.$_[0];
  $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
  if (@_ > 1) {
    if (not defined $self->{params}->{$n}) {
      push @{$self->{param_names}}, $n;
    }
    $self->{params}->{$n} = ''.$_[1];
  } else {
    return $self->{params}->{$n};
  }
}

sub attrs ($) {
  return [@{$_[0]->{param_names}}];
} # attrs

sub apache_bug ($) {
  return $_[0]->{apache_bug};
} # apache_bug

## ------ Type properties ------

sub _type_def ($) {
  my $self = shift;
  return do {
    require Web::MIME::_TypeDefs;
    $Web::MIME::_TypeDefs::Type->{$self->type};
  }; # or undef
} # _type_def

sub _subtype_def ($) {
  my $self = shift;
  return (($self->_type_def or {})->{subtype}->{$self->subtype}); # or undef
} # _subtype_def

## Whether the media type is a "styling language" or not.  The Web
## Applications 1.0 specification does not define exactly what is a
## "styling langauge" except that the spec implies at least |text/css|
## is a styling language.
sub is_styling_lang ($) {
  my $self = shift;
  return (($self->_subtype_def or {})->{styling});
} # is_styling_lang

sub is_scripting_lang ($) {
  my $self = shift;
  my $lang = ($self->_subtype_def or {})->{scripting_language} || '';
  return $lang && $lang ne 'no';
} # is_scripting_lang

sub is_javascript ($) {
  my $self = shift;
  return 'javascript' eq (($self->_subtype_def or {})->{scripting_language} || '');
} # is_javascript

sub is_image ($) {
  return $_[0]->{type} eq 'image';
} # is_image

sub is_audio_or_video ($) {
  my $self = shift;
  return 1 if $self->{type} eq 'audio' or $self->{type} eq 'video';
  return (($self->_subtype_def or {})->{audiovideo});
} # is_audio_or_video

## What is "text-based" media type is unclear.
sub is_text_based ($) {
  my $self = shift;

  my $type = $self->type;
  return 1 if {text => 1, message => 1, multipart => 1}->{$type};

  my $subtype = $self->subtype;
  return 1 if $subtype =~ /\+xml\z/;

  return (($self->_subtype_def or {})->{text});
} # is_text_based

sub is_composite_type ($) {
  my $self = shift;
  my $type = $self->type;
  return ($type eq 'multipart' or $type eq 'message');
} # is_composite_type

## This method returns whether the type is an "XML MIME type"
## according to the Web Applications 1.0's definition.
##
## Although Atom 1.0 [RFC 4287] cites "XML media types" from RFC 3023
## (which titles "XML Media Types"), RFC 3023 does not define the term
## "XML media types" or "XML MIME types.  Note that RFC 3023 does not
## use the term "XML media types" other than as the document title but
## does use "XML MIME types" in its appendix.
sub is_xml_mime_type ($) {
  my $self = shift;

  my $subtype = $self->subtype;
  if ($subtype eq 'xml') {
    my $type = $self->type;
    return ($type eq 'text' or $type eq 'application');
  } elsif ($subtype =~ /\+xml\z/) {
    return 1;
  } else {
    return 0;
  }
} # is_xml_mime_type

## ------ Serialization ------

sub mime_type_portion ($) {
  return $_[0]->{type} . '/' . $_[0]->{subtype};
} # mime_type_portion

my $non_token = qr/[^\x21\x23-\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]/;

sub as_valid_mime_type_with_no_params ($) {
  my $self = shift;

  my $type = $self->type;
  my $subtype = $self->subtype;
  if (not length $type or not length $subtype or
      $type =~ /$non_token/o or $subtype =~ /$non_token/o) {
    return undef;
  }

  return $type . '/' . $subtype;
} # as_valid_mime_type_with_no_params

sub as_valid_mime_type ($) {
  my $self = shift;
  
  my $ts = $self->as_valid_mime_type_with_no_params;
  return undef unless defined $ts;

  for my $attr (@{$self->attrs}) {
    return undef if not length $attr or $attr =~ /$non_token/o;
    $ts .= ';' . $attr . '=';

    my $value = $self->{params}->{$attr};
    return undef if $value =~ /[^\x00-\xFF]/;

    if (not length $value or $value =~ /$non_token/o) {
      $value =~ s/([\x22\x5C])/\\$1/g;
      $ts .= '"' . $value . '"';
    } else {
      $ts .= $value;
    }
  }

  return $ts;
} # as_valid_mime_type

## ------ Conformance checking ------

sub validate ($$;%) {
  my ($self, $onerror, %args) = @_;

  ## NOTE: Attribute duplication are not error, though its semantics
  ## is not defined.  See
  ## <https://suika.suikawiki.org/gate/2005/sw/%E5%AA%92%E4%BD%93%E5%9E%8B/%E5%BC%95%E6%95%B0>.
  ## However, a Web::MIME::Type object cannot represent duplicate
  ## attributes and is reported in the parsing phase.

  my $type = $self->type;
  my $subtype = $self->subtype;

  ## NOTE: RFC 2045 (MIME), RFC 7230 (HTTP/1.1), and RFC 4288 (IMT
  ## registration) have different requirements on type and subtype
  ## names.
  my $type_syntax_error;
  my $subtype_syntax_error;
  if ($type !~ /\A[A-Za-z0-9!#\$&.+^_-]{1,127}\z/) {
    $onerror->(type => 'MIME type:bad type',
               level => $ErrorLevels->{must}, # RFC 4288 4.2.
               value => $type);
    $type_syntax_error = 1;
  }
  if ($subtype !~ /\A[A-Za-z0-9!#\$&.+^_-]{1,127}\z/) {
    $onerror->(type => 'MIME type:bad subtype',
               level => $ErrorLevels->{must}, # RFC 4288 4.2.
               value => $subtype);
    $subtype_syntax_error = 1;
  }

  my $type_def = $self->_type_def;
  my $has_param;

  if ($type =~ /^x-/) {
    $onerror->(type => 'IMT:private type',
               level => $ErrorLevels->{mime_strongly_discouraged},
               value => $type); # RFC 2046 6.
    ## NOTE: "discouraged" in RFC 4288 3.4.
  } elsif (not $type_def or not $type_def->{iana}) {
  #} elsif ($type_def and not $type_def->{iana}) {
    ## NOTE: Top-level type is seldom added.
    
    ## NOTE: RFC 2046 6. "Any format without a rigorous and public
    ## definition must be named with an "X-" prefix" (strictly
    ## speaking, this is not an author requirement, but a requirement
    ## for media type specfication author, and it does not restrict
    ## use of unregistered value).
    $onerror->(type => 'IMT:unregistered type',
               level => $ErrorLevels->{mime_must},
               value => $type)
        unless $type_syntax_error;
  }

  if ($type_def) {
    my $subtype_def = $type_def->{subtype}->{$subtype};

    if ($subtype =~ /^x[-\.]/) {
      $onerror->(type => 'IMT:private subtype',
                 level => $ErrorLevels->{mime_discouraged},
                 value => $type . '/' . $subtype);
      ## NOTE: "x." and "x-" are discouraged in RFC 4288 3.4.
    } elsif ($subtype_def and not $subtype_def->{iana} and $type_def->{iana}) {
      ## NOTE: RFC 2046 6. "Any format without a rigorous and public
      ## definition must be named with an "X-" prefix" (strictly, this
      ## is not an author requirement, but a requirement for media
      ## type specfication author and it does not restrict use of
      ## unregistered value).
      $onerror->(type => 'IMT:unregistered subtype',
                 level => $ErrorLevels->{mime_must},
                 value => $type . '/' . $subtype);
    }
    
    if ($subtype_def) {
      ## NOTE: Semantics and relationship to conformance of the
      ## "intended usage" keywords in the IMT registration template is
      ## not defined anywhere.
      if ($subtype_def->{obsolete}) {
        $onerror->(type => 'IMT:obsolete subtype',
                   level => $ErrorLevels->{warn},
                   value => $type . '/' . $subtype);
      } elsif ($subtype_def->{limited_use}) {
        $onerror->(type => 'IMT:limited use subtype',
                   level => $ErrorLevels->{warn},
                   value => $type . '/' . $subtype);        
      }

      for my $attr (@{$self->attrs}) {
        my $value = $self->param ($attr);

        my $attr_syntax_error;
        if ($attr !~ /\A[A-Za-z0-9!#\$&.+^_-]{1,127}\z/) {
          $onerror->(type => 'params:bad name',
                     level => $ErrorLevels->{mime_fact}, # RFC 4288 4.3.
                     value => $attr);
          $attr_syntax_error = 1;
        }

        $has_param->{$attr} = 1;
        my $param_def = $subtype_def->{params}->{$attr}
            || $type_def->{params}->{$attr};
        if ($param_def) {
          if (defined $param_def->{syntax}) {
            if ($param_def->{syntax} eq 'mime-charset') { # RFC 2978
              ## XXX Should be checked against IANA charset registry.
              if ($value =~ /[^A-Za-z0-9!#\x23%&'+^_`{}~-]/) {
                $onerror->(type => 'value syntax error:'.$attr, level => 'm');
              }
            } elsif ($param_def->{syntax} eq 'token') { # RFC 2046
              ## NOTE: Though the definition of |token| differs in RFC
              ## 2046 and in RFC 7230, parameters are defined in terms
              ## of MIME RFCs such that this should be checked against
              ## MIME's definition.  Use of "{" and "}" in HTTP
              ## contexts is rejected anyway at the parsing phase.
              if ($value =~ /[^\x21\x23-\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7E]/) {
                $onerror->(type => 'value syntax error:'.$attr, level => 'm');
              }
            }
            ## XXX add support for syntax |MIME date-time|
          } elsif ($attr eq 'boundary' and $type eq 'multipart') {
            if ($value !~ /\A[0-9A-Za-z'()+_,.\x2F:=?-]{0,69}[0-9A-Za-z'()+_,.\x2F:=?\x20-]\z/) {
              $onerror->(type => 'boundary:syntax error',
                         level => $ErrorLevels->{mime_fact}, # TODO: correct?
                         value => $value);
            }
          }
           
          if ($param_def->{obsolete}) {
            $onerror->(type => 'IMT:obsolete parameter',
                       level => $ErrorLevels->{$param_def->{obsolete}},
                       value => $attr);
            ## NOTE: The value of |$param_def->{obsolete}|, if it has
            ## a true value, must be "mime_fact", which represents
            ## that the parameter is defined in a previous version of
            ## the MIME specification (or a related specification) and
            ## then removed or marked as obsolete such that it seems
            ## that use of that parameter is made non-conforming
            ## without using any explicit statement on that fact.
          }
        }
        if ($attr_syntax_error) {
          #
        } elsif (not $param_def) { # XXX or not $param_def->{iana}) {
          if ($subtype =~ /\./ or $subtype =~ /^x-/ or $type =~ /^x-/) {
            ## NOTE: The parameter names "SHOULD" be fully specified
            ## for personal or vendor tree subtype [RFC 4288].
            ## Therefore, there might be unknown parameters and still
            ## conforming.
            $onerror->(type => 'IMT:unknown parameter',
                       level => $ErrorLevels->{uncertain},
                       value => $attr);
          } else {
            ## NOTE: The parameter names "MUST" be fully specified for
            ## standard tree.  Therefore, unknown parameter is
            ## non-conforming, unless it is standardized later.
            $onerror->(type => 'IMT:parameter not allowed',
                       level => $ErrorLevels->{mime_fact},
                       value => $attr);
          }
        }
      }

      unless ($args{no_required_param}) {
        for (keys %{$subtype_def->{params} or {}}) {
          if ($subtype_def->{params}->{$_}->{required} and
              not $has_param->{$_}) {
            $onerror->(type => 'IMT:parameter missing',
                       level => $ErrorLevels->{mime_fact},
                       text => $_,
                       value => $type . '/' . $subtype);
          }
        }
      }
    } else {
      ## NOTE: Since subtypes are frequently added to the IANAREG and
      ## such that our database might be out-of-date, we don't raise
      ## an error for an unknown subtype, instead we report an
      ## "uncertain" status.
      $onerror->(type => 'IMT:unknown subtype',
                 level => $ErrorLevels->{uncertain},
                 value => $type . '/' . $subtype)
          if not $subtype_syntax_error and not $subtype =~ /^x[-.]/ and
             not $type =~ /^x-/;
    }

    unless ($args{no_required_param}) {
      for (keys %{$type_def->{params} or {}}) {
        if ($type_def->{params}->{$_}->{required} and
            not $has_param->{$_}) {
          $onerror->(type => 'IMT:parameter missing',
                     level => $ErrorLevels->{mime_fact},
                     text => $_,
                     value => $type . '/' . $subtype);
        }
      }
    }
  }
} # check_imt

1;

=head1 LICENSE

Copyright 2007-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

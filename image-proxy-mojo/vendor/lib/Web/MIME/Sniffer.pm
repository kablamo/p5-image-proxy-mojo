package Web::MIME::Sniffer;
use strict;
use warnings;
our $VERSION = '1.20';
use Web::MIME::Type;
use Web::MIME::_TypeDefs;

sub new_from_context ($$) {
  return bless {
    context => $_[1],
    supported_image_types => {},
    supported_audio_or_video_types => {},
  }, $_[0];
} # new_from_context

sub is_http ($;$) {
  if (@_ > 1) {
    $_[0]->{is_http} = $_[1];
  }
  return $_[0]->{is_http};
} # is_http

sub supported_image_types ($) {
  return $_[0]->{supported_image_types};
} # supported_image_types

sub supported_audio_or_video_types ($) {
  return $_[0]->{supported_audio_or_video_types};
} # supported_audio_or_video_types

sub _mime ($) {
  return Web::MIME::Type->parse_web_mime_type ($_[0]);
} # _mime

sub _t ($$) {
  for (@{$_[0]}) {
    if ($_[1] =~ /^$_->[0]/) {
      return _mime $_->[1];
    }
  }
  return undef;
} # _t

## <https://mimesniff.spec.whatwg.org/#signature-for-mp4>
sub _mp4 ($) {
  my $length = length $_[0];
  return 0 if $length < 12;
  my $box_size = unpack 'N', substr $_[0], 0, 4;
  return 0 if $length < $box_size or ($box_size % 4) != 0;
  return 0 unless "\x66\x74\x79\x70" eq substr $_[0], 4, 4;
  return 1 if "\x6D\x70\x34" eq substr $_[0], 8, 3;
  my $bytes_read = 16;
  while ($bytes_read < $box_size) {
    return 1 if "\x6D\x70\x34" eq substr $_[0], $bytes_read, 3;
    $bytes_read += 4;
  }
  return 0;
} # _mp4

## <https://mimesniff.spec.whatwg.org/#signature-for-webm>
sub _webm ($) {
  my $length = length $_[0];
  return 0 if $length < 4;
  return 0 unless "\x1A\x45\xDF\xA3" eq substr $_[0], 0, 4;
  my $iter = 4;
  while ($iter < $length and $iter < 38) {
    if ("\x42\x82" eq substr $_[0], $iter, 2) {
      $iter += 2;
      return 0 if $iter >= $length;
      my $number_size = do { # parse a |vint|
        my $mask = 128;
        my $max_vint_length = 8;
        my $number_size = 1;
        while ($number_size < $max_vint_length and
               $number_size < $length) {
          last if $mask & ord substr $_[0], $iter + $number_size - 1, 1;
          $mask >>= 1;
          $number_size++;
        }
        #my $index = 0;
        #my $parsed_number = ~$mask & ord substr $_[0], $iter + $index, 1;
        #$index++;
        #my $bytes_remaining = $number_size;
        #while ($bytes_remaining) {
        #  $parsed_number <<= 8;
        #  $parsed_number |= ord substr $_[0], $iter + $index, 1;
        #  $index++;
        #  last if $index >= $length;
        #  $bytes_remaining--;
        #}
        $number_size;
      };
      $iter += $number_size;
      return 0 unless $iter < $length - 4;
      { # matching a padded sequence
        pos ($_[0]) = $iter;
        return 1 if $_[0] =~ /\G\x00*\x77\x65\x62\x6D/g;
      }
    }
    $iter++;
  }
  return 0;
} # _webm

sub _match_mp3_header ($$) {
  my $length = length $_[0];
  my $s = $_[1];
  return 0 if $length < $s + 4;
  return 0 if (ord substr $_[0], $s, 1) != 0xFF and
      ((ord substr $_[0], $s + 1, 1) & 0xE0) != 0xE0;
  return 0 unless 1 == (((ord substr $_[0], $s + 1, 1) & 0x06) >> 1);
  return 0 if 15 == (((ord substr $_[0], $s + 2, 1) & 0xF0) >> 4);
  return 0 if 3 == (((ord substr $_[0], $s + 2, 1) & 0x0C) >> 2);
  return 1;
} # _match_mp3_header

## <https://mimesniff.spec.whatwg.org/#signature-for-mp3-without-id3>
sub _mp3 ($) {
  my $length = length $_[0];
  my $s = 0;
  return 0 unless _match_mp3_header $_[0], $s;
  my $skipped_bytes = do {
    ## parse an mp3 frame
    my $version = ((ord substr $_[0], $s + 1, 1) & 0x18) >> 3;
    my $bitrate_index = ((ord substr $_[0], $s + 2, 1) & 0xF0) >> 4;
    my $bitrate;
    if ($version & 0x01) {
      $bitrate = $Web::MIME::_TypeDefs::MP3->{mp25rates}->[$bitrate_index];
    } else {
      $bitrate = $Web::MIME::_TypeDefs::MP3->{mp3rates}->[$bitrate_index];
    }
    my $samplerate_index = ((ord substr $_[0], $s + 2, 1) & 0x0C) >> 2;
    my $samplerate = $Web::MIME::_TypeDefs::MP3->{samplerates}->[$samplerate_index];
    my $pad = ((ord substr $_[0], $s + 2, 1) & 0x02) >> 1;

    ## compute an mp3 frame size
    my $scale = ($version & 1) == 0 ? 72 : 144;
    my $size = int ($bitrate * $scale / $samplerate);
    $size++ unless $pad == 0;
    $size;
  };
  $s += 4;
  return 0 if $skipped_bytes < 4 or $skipped_bytes > $length - $s;
  $s += $skipped_bytes;
  return _match_mp3_header $_[0], $s;
} # _mp3

## <https://mimesniff.spec.whatwg.org/#sniffing-a-mislabeled-feed>
sub _feed_or_html ($) {
  pos ($_[0]) = 0;

  if (substr ($_[0], 0, 3) eq "\xEF\xBB\xBF") {
    pos ($_[0]) = 3; # skip UTF-8 BOM.
  }

  1 while $_[0] =~ /\G(?:[\x09\x20\x0A\x0C\x0D]+|<!--.*?-->|<![^>]*>|<\?.*?\?>)/gcs;
  return _mime 'text/html' unless $_[0] =~ /\G</gc;

  if ($_[0] =~ /\Grss/gc) {
    return _mime 'application/rss+xml';
  } elsif ($_[0] =~ /\Gfeed/gc) {
    return _mime 'application/atom+xml';
  } elsif ($_[0] and $_[0] =~ /\Grdf:RDF/gc) {
    # 
  } else {
    return _mime 'text/html';
  }

  my $pos = pos $_[0];
  if ($_[0] =~ m{\G.*?\Qhttp://www.w3.org/1999/02/22-rdf-syntax-ns#\E}gs) {
    pos ($_[0]) = $pos;
    if ($_[0] =~ m{\G.*?\Qhttp://purl.org/rss/1.0/\E}gs) {
      return _mime 'application/rss+xml';
    }
  }

  return _mime 'text/html';
} # _feed_or_html

sub detect ($$$) {
  my ($self, $mime, undef) = @_;

  my $sniffer = 0;
  # 0b10000000000 scriptable
  # 0b01000000000 non-scriptable
  # 0b00100000000 bom1
  # 0b00010000000 bom2
  # 0b00001000000 feed or html (unused)
  # 0b00000100000 image
  # 0b00000010000 audio or video
  # 0b00000001000 archive
  # 0b00000000100 font
  # 0b00000000010 text track
  # 0b00000000001 binary

  my $official_type = defined $mime ? $mime->mime_type_portion : undef;
  if ($self->{context} eq 'navigate') {
    if (not defined $official_type or
        $official_type eq 'unknown/unknown' or
        $official_type eq 'application/unknown' or
        $official_type eq '*/*') {
      $sniffer = 0b11100110001;
      undef $mime;
    } elsif ($mime->apache_bug and $self->is_http) {
      $sniffer = 0b00010000001;
    } elsif ($mime->is_xml_mime_type) {
      return $mime;
    } elsif ($official_type eq 'text/html') {
      return _feed_or_html $_[2];
    } elsif ($self->{supported_image_types}->{$official_type} and
             $mime->is_image) {
      $sniffer = 0b00000100000;
    } elsif ($self->{supported_audio_or_video_types}->{$official_type} and
             $mime->is_audio_or_video) {
      $sniffer = 0b00000010000;
    } else {
      #
    }
  } elsif ($self->{context} eq 'image') {
    unless (defined $mime and $mime->is_xml_mime_type) {
      $sniffer = 0b00000100000;
    }
  } elsif ($self->{context} eq 'audio_or_video') {
    unless (defined $mime and $mime->is_xml_mime_type) {
      $sniffer = 0b00000010000;
    }
  } elsif ($self->{context} eq 'font') {
    unless (defined $mime and $mime->is_xml_mime_type) {
      $sniffer = 0b00000000100;
    }
  } elsif ($self->{context} eq 'text_track') {
    unless (defined $mime and $mime->is_xml_mime_type) {
      $sniffer = 0b00000000010;
    }
  } elsif ($self->{context} eq 'object') {
    if (not defined $official_type or
        $official_type eq 'unknown/unknown' or
        $official_type eq 'application/unknown' or
        $official_type eq '*/*') {
      $sniffer = 0b11100110001;
      undef $mime;
    } elsif ($official_type eq 'text/plain') {
      $sniffer = 0b00010000001;
    }
  } else {
    die "Bad context |$self->{context}|";
  }

  if ($sniffer & 0b10000000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{scriptable}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b01000000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{non_scriptable}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00100000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{bom1}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00010000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{bom2}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000100000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{image}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000010000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{audio_or_video}, $_[2];
    return $computed if defined $computed;

    return _mime 'video/mp4' if _mp4 $_[2];
    return _mime 'video/webm' if _webm $_[2];
    return _mime 'audio/mpeg' if _mp3 $_[2];
  }

  if ($sniffer & 0b00000001000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{archive}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000000100) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{font}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000000010) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{text_track}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000000001) {
    return _mime 'application/octet-stream'
        if $_[2] =~ /[\x00-\x08\x0B\x0E-\x1A\x1C-\x1F]/;
  }

  return $mime || _mime 'text/plain';
} # detect

1;

=head1 LICENSE

Copyright 2007-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

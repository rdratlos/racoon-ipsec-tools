#!/usr/bin/env perl
# gen-kate-syntax.pl — generate a Kate syntax-highlighting definition
# for racoon.conf by parsing the flex grammar in src/racoon/cftoken.l.
#
# Usage:
#   scripts/gen-kate-syntax.pl [path/to/cftoken.l] > misc/kate/racoon.xml
#
# Run without arguments from the repository root, or pass an explicit
# path to cftoken.l. Output is written to stdout so the caller decides
# where the generated file goes (see misc/kate/Makefile.am).

use strict;
use warnings;

my $input = shift @ARGV // "src/racoon/cftoken.l";

open(my $fh, "<", $input)
    or die "gen-kate-syntax.pl: cannot open $input: $!\n";
my @lines = <$fh>;
close($fh);
chomp(@lines);

# Only the flex rules section (between the two bare "%%" markers) contains
# the keyword patterns we care about; everything else is C code.
my ($rules_start, $rules_end);
for my $i (0 .. $#lines) {
    if ($lines[$i] =~ /^%%\s*$/) {
        if (!defined $rules_start) {
            $rules_start = $i + 1;
        } else {
            $rules_end = $i - 1;
            last;
        }
    }
}
die "gen-kate-syntax.pl: could not find flex rules section in $input\n"
    unless defined $rules_start && defined $rules_end;

# A bare-word lexer pattern, optionally prefixed by a <START_CONDITION> and
# optionally alternated with '|', e.g. "des_iv64", "utf-16le", "B|byte|bytes".
# Patterns built from named references ({ws}, {bcl}, ...) or regex
# metacharacters are deliberately not matched: they are punctuation or
# free-form values, not literal keywords worth highlighting individually.
my $word    = qr/[A-Za-z][A-Za-z0-9_-]*/;
my $pattern = qr/$word(?:\|$word)*/;

# Token names that identify an enumerated *value* keyword (e.g. "sha1",
# "yes", "notify") rather than a directive/option name. Anything not
# listed here falls back to the generic "Keyword" bucket.
my %category_of_token = (
    ALGORITHMTYPE        => "DataType",
    IDENTIFIERTYPE       => "DataType",
    IDENTIFIERQUAL       => "DataType",
    UL_PROTO             => "Protocol",
    BOOLEAN              => "Constant",
    SWITCH               => "Constant",
    LOGLEV               => "Constant",
    PATHTYPE             => "Constant",
    EXCHANGETYPE         => "Constant",
    DOITYPE              => "Constant",
    SITUATIONTYPE        => "Constant",
    CERT_X509            => "Constant",
    CERT_PLAINRSA        => "Constant",
    GENERATE_LEVEL       => "Constant",
    PROPOSAL_CHECK_LEVEL => "Constant",
    GSS_ID_ENCTYPE       => "Constant",
);

sub categorize {
    my ($token) = @_;
    return $category_of_token{$token} if exists $category_of_token{$token};
    return "Unit" if $token =~ /^UNITTYPE_/;
    return "Keyword";
}

my %words;    # category => { word => 1 }
my $i = $rules_start;
while ($i <= $rules_end) {
    my $line = $lines[$i];

    if ($line =~ /^\s*(?:<$word(?:,$word)*>)?($pattern)\s*\{(.*)$/) {
        my ($pat, $rest) = ($1, $2);

        # Collect the action block, which may span multiple lines (e.g.
        # the #ifdef ENABLE_HYBRID guarded rules).
        my $action = $rest;
        my $depth  = 1 + (() = $rest =~ /\{/g) - (() = $rest =~ /\}/g);
        while ($depth > 0 && $i + 1 <= $rules_end) {
            $i++;
            my $next = $lines[$i];
            $action .= "\n$next";
            $depth += (() = $next =~ /\{/g) - (() = $next =~ /\}/g);
        }

        if ($action =~ /return\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/) {
            my $token    = $1;
            my $category = $action =~ /BEGIN\s+S_[A-Za-z0-9_]+/
                ? "Section"
                : categorize($token);
            $words{$category}{$_} = 1 for split /\|/, $pat;
        }
    }

    $i++;
}

die "gen-kate-syntax.pl: no keywords extracted from $input\n"
    unless %words;

sub emit_list {
    my ($name, $attr) = @_;
    return "" unless $words{$attr};
    my @sorted = sort keys %{ $words{$attr} };
    my $out = qq{<list name="$name">\n};
    $out .= qq{<item>$_</item>\n} for @sorted;
    $out .= qq{</list>\n};
    return $out;
}

my %list_name_of = (
    Section  => "sections",
    Keyword  => "keywords",
    DataType => "datatypes",
    Constant => "constants",
    Unit     => "units",
    Protocol => "protocols",
);

print <<'HEADER';
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE language>
<language name="Racoon IPSec Tools" version="2" kateversion="5.62" section="Configuration" extensions="racoon.conf;racoon-*.conf;*.racoon.conf" indenter="cstyle" author="racoon-ipsec-tools contributors" license="BSD-3-Clause">
<highlighting>
HEADER

for my $category (qw(Section Keyword DataType Constant Unit Protocol)) {
    print emit_list($list_name_of{$category}, $category);
}

print <<'BODY';
<contexts>
<context name="Normal" attribute="Normal Text" lineEndContext="#stay">
<keyword String="sections" attribute="Section"/>
<keyword String="keywords" attribute="Keyword"/>
<keyword String="datatypes" attribute="DataType"/>
<keyword String="constants" attribute="Constant"/>
<keyword String="units" attribute="Unit"/>
<keyword String="protocols" attribute="Protocol"/>
<DetectChar char="&quot;" attribute="String" context="String"/>
<RegExpr String="0x[0-9A-Fa-f]+" attribute="Hex"/>
<RegExpr String="[0-9A-Fa-f]+([:.][0-9A-Fa-f:.]*)+(%[A-Za-z0-9]+)?" attribute="Address"/>
<Int attribute="Decimal"/>
<DetectChar char="{" attribute="Operator" beginRegion="Block"/>
<DetectChar char="}" attribute="Operator" endRegion="Block"/>
<AnyChar String="[];," attribute="Operator"/>
<DetectChar char="#" attribute="Comment" context="Comment"/>
</context>
<context name="String" attribute="String" lineEndContext="#pop">
<DetectChar char="&quot;" attribute="String" context="#pop"/>
</context>
<context name="Comment" attribute="Comment" lineEndContext="#pop">
<IncludeRules context="##Comments"/>
</context>
</contexts>
<itemDatas>
<itemData name="Normal Text" defStyleNum="dsNormal"/>
<itemData name="Section" defStyleNum="dsKeyword"/>
<itemData name="Keyword" defStyleNum="dsKeyword"/>
<itemData name="DataType" defStyleNum="dsDataType"/>
<itemData name="Constant" defStyleNum="dsConstant"/>
<itemData name="Unit" defStyleNum="dsBuiltIn"/>
<itemData name="Protocol" defStyleNum="dsBuiltIn"/>
<itemData name="String" defStyleNum="dsString"/>
<itemData name="Hex" defStyleNum="dsBaseN"/>
<itemData name="Address" defStyleNum="dsOthers"/>
<itemData name="Decimal" defStyleNum="dsDecVal"/>
<itemData name="Operator" defStyleNum="dsOperator"/>
<itemData name="Comment" defStyleNum="dsComment"/>
</itemDatas>
</highlighting>
<general>
<comments>
<comment name="singleLine" start="#"/>
</comments>
<keywords casesensitive="1"/>
</general>
</language>
BODY

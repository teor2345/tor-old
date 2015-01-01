#!/usr/bin/perl -p -w -i

# Convert signed left shifts into safe SHLnn() macros
# Usage: ./safe_shl.pl < file.c
# See curve25519_donna and ed25519/ref10 for examples

# This requires existing SHLnn() macros defined using appropriate types
# The generic version is in torint.h as OVERFLOW_SAFE_SIGNED_LSHIFT,
# which takes the shiftee, left shift amount, unsigned, and signed types.

BEGIN { %vartypes = (); }

if (/^[{}]/) {
    %vartypes = ();
}

if (/^ *crypto_int(\d+) +([a-zA-Z_][_a-zA-Z0-9]*)/) {
    $vartypes{$2} = $1;
} elsif (/(?:(?:^ *)|(?:\())(?:const +)?s(\d+) +([a-zA-Z_][_a-zA-Z0-9]*)(\[\d+\])?/) {
    # capture s\d\d declared in function arguments, and/or as arrays
    if (defined $3) {
        $vartypes{"*".$2} = $1;
    } else {
        $vartypes{$2} = $1;
    }
} elsif (/^ *(?:signed +)?char +([a-zA-Z_][_a-zA-Z0-9]*)/) {
    $vartypes{$1} = '8';
} elsif (/(?:(?:^ *)|(?:\())limb +((?:\*)?[a-zA-Z_][_a-zA-Z0-9]*)/) {
    # capture limb declared in function arguments, and/or as pointers
    $vartypes{$1} = '64';
}

# This fixes at most one shift per line. But that's all the code does.
if (/([a-zA-Z_][a-zA-Z_0-9]*)(?:\[\d+\])? *<< *(\d+)/) {
    $v = $1;
    if (exists $vartypes{$v}) {
        # replace a << n
        s/$v *<< *(\d+)/SHL$vartypes{$v}($v,$1)/;
    } elsif (exists $vartypes{"*".$v}) {
        # replace a[i] << n
        s/$v(\[\d+\]) *<< *(\d+)/SHL$vartypes{"*".$v}($v$1,$2)/;
    }
} elsif (/([a-zA-Z_][a-zA-Z_0-9]*)(?:\[\d+\])? *<<= *(\d+)/) {
    $v = $1;
    if (exists $vartypes{$v}) {
        # replace a <<= n
        s/$v *<<= *(\d+)/$v = SHL$vartypes{$v}($v,$1)/;
    } elsif (exists $vartypes{"*".$v}) {
        # replace a[i] <<= n
        s/$v(\[\d+\]) *<<= *(\d+)/$v$1 = SHL$vartypes{"*".$v}($v$1,$2)/;
    }
}

# remove extra parenthesis
s/\(SHL64\((.*)\)\)/SHL64\($1\)/;
s/\(SHL32\((.*)\)\)/SHL32\($1\)/;
s/\(SHL8\((.*)\)\)/SHL8\($1\)/;

# print %vartypes;

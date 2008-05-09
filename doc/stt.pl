#! /usr/bin/perl

# usage: 
#     stt [OPTIONS] FILE [...]
#     stt -M FILE [...]
#     stt -c TEMPLATE FILE
#
# OPTIONS:
#    -L TEMPLATEDIR
#    -M
# 
# Updates files that depend on DreamWeaver-style templates.  Examines
# each FILE given on the command-line to see if it appears to depend
# on a DreamWeaver-style template, and if so, updates that file from
# the template whose name is mentioned in the <!-- #BeginTemplate
# "template" --> block in the file.  If "-L TEMPLATEDIR" is specified,
# looks for the templates themselves in TEMPLATEDIR.  If more than one
# "-L TEMPLATEDIR" is given, looks for each template in each
# TEMPLATEDIR specified, in the order given.  If a template is not
# found in any of the TEMPLATEDIRs, or if no "-L TEMPLATEDIR"
# arguments are present, looks for the template in the current
# directory.  The original version of each file is saved with a "~"
# suffix.
#
# If the -M option is given, does not actually update any files; just
# parses each file to see what template it depends on, and outputs
# a make-style dependency list for the files.
#
#
# Mark Phillips
#
# $Log: stt,v $
# Revision 1.1.1.1  2003/03/20 20:05:17  mphillips
# initial import
#

use strict;

$| = 1;

# Hash of templates.  The keys to this hash are template files
# names.  Each hash value is the list returned by calling
# parse_stt() for that template.
my %templates = ();
my %template_paths = ();


# Parse options
my $dodeps = 0;
my $create = 0;
my ($template,$file);
my @TEMPLATEDIRS = ();
while ($ARGV[0] =~ m/^-/) {
    if ($ARGV[0] eq "-M") {
	$dodeps = 1;
	shift;
    } elsif ($ARGV[0] eq "-c") {
	shift;
	$create = 1;
	$template = shift;
	$file     = shift;
    } elsif ($ARGV[0] eq "-L") {
	shift;
	my $dir = shift;
	$dir =~ s|/$||;  # remove trailing '/', if any
	if (! -d $dir) {
	    die "Can't read directory $dir\n";
	} else {
	    push(@TEMPLATEDIRS, $dir);
	}
    }
}

if ($create) {
    if (-f $file) {
	die "File already exists: $file\n";
    }
    open(OUT, ">$file") ||
	die "Can't write file $file\n";
    open(IN, "<$template") ||
	die "Can't read template $template\n";
    print OUT qq|<!-- #BeginTemplate "$template" -->\n|;
    while (<IN>) {
        print OUT $_;
    }
    print OUT qq|<!-- #EndTemplate -->\n|;
    close(OUT);
    close(IN);
    exit;
}

if (!@ARGV) {
    die "no files to process\n";
}

my $file;
while ($file = shift) {
    if (! -f $file) {
	die "Can't read input file $file\n";
    }
    if (! -w $file) {
	die "No permission to modify file $file\n";
    }
    my ($F_text, @F_editables) = @{parse_stt($file)};
    
    my ($template_name,$pre,$post) = parse_templated_file_text($F_text);
    if (!$template_name) {
	print "warning: $file does not appear to use a template; skipping it\n"
	    unless $dodeps;
	next;
    }
    if (!$templates{$template_name}) {
	my $template_path = find_template($template_name);
	if (!$template_path) {
	    print "warning: can't locate template $template_name; skipping file $file\n"
		unless $dodeps;
	    next;
	}
	$templates{$template_name} = parse_stt($template_path);
	$template_paths{$template_name} = $template_path;
    }

    if ($dodeps) {
	print "$file: $template_paths{$template_name}\n";
	next;
    }
    print "applying template $template_paths{$template_name} to $file\n";

    my ($T_text, @T_editables) = @{$templates{$template_name}};

    my $output = $T_text;
    my ($e,$name,$text);
    my %editables_done = ();
    foreach $e (@F_editables) {
	$name  = $e->{name};
	$text = $e->{text};
	$output =~ s|%%%EDITABLE_${name}_EDITABLE%%%|$text|s;
	$editables_done{$name} = 1;
    }
    foreach $e (@T_editables) {
	$name = $e->{name};
	$text = $e->{text};
	if (!$editables_done{$name}) {
	    $output =~ s|%%%EDITABLE_${name}_EDITABLE%%%|$text|s;
	}
    }
    rename($file, "$file~");
    open(OUT, ">$file");
    print OUT $pre;
    print OUT $output;
    print OUT $post;
    close(OUT);
}

# This function parses a DreamWeaver-style input file (template
# or HTML file), processing blocks delimited by
# 
#     <!-- #BeginEditable "name" -->
# 
# and
# 
#     <!-- #EndEditable -->
# 
# Each such block is called an "editable".  The string in quotes in
# the BeginEditable line is called the name of the editable, and any
# text between the above two markers is called the text of the
# editable.  This function returns a reference to a two-element list.
# The first element in the return list is a string which consists of
# the entire text of the input file, with the text of each editable
# replaced with the special string
# 
#     %%%EDITABLE_name_EDITABLE%%%
# 
# The second element of the return list is a list of hash references,
# one for each editable in the file.  Each such hash has two keys,
# "name", and "text", whose values give the name and text of that
# editable.
sub parse_stt {
    my $sttfile = shift;
    if (! -r $sttfile) {
	die "can't read file $sttfile\n";
    }
    open(IN, "<$sttfile");
    my $rawtext = "";
    while (<IN>) { $rawtext .= $_; }
    close(IN);

    my $text = "";
    my @editables = ();

    while ( $rawtext =~ m|<!--\s*#BeginEditable\s*|sg ) {

	 # Set $i to the position at end of above match, i.e. at beginning
	 # of the quoted name of this editable region
	 my $i = pos($rawtext);

	 # Save text up to $i
	 $text .= substr($rawtext, 0, $i);

	 # Chop off the saved text from the beginning of $rawtext
	 $rawtext     = substr($rawtext, $i);

	 # Get the name of the editable
         my $editablename;
	 if ( ($editablename) = ($rawtext =~ m|^\s*"([a-zA-Z0-9_-]*)"\s*-->|s) ) {
	     # Add the quoted name to the text
	     $text .= qq|"$editablename" -->|;
	     # Remove it from $rawtext
	     $rawtext =~ s|^\s*"([a-zA-Z0-9_-]*)"\s*-->||s;
	 } else {
	     die "Can't find name of Editable region (near char $i in file $sttfile)\n";
	 }
	 # Add the subst string for this editable to the text
	 $text .= "%%%EDITABLE_${editablename}_EDITABLE%%%";

	 # Now read the text of the editable itself, and the closing #EndEditable stuff
	 if ( $rawtext =~ m|<!--\s*#EndEditable\s*-->|sg ) {
	      $i = pos($rawtext);
	      my $editabletext = substr($rawtext, 0, $i);
	      $editabletext =~ s|<!--\s*#EndEditable\s*-->||s;
	      $text .= qq|<!-- #EndEditable -->|;
	      $rawtext = substr($rawtext, $i);
	      # Add this editable to the list
	      my %editable = ();
	      $editable{'name'} = $editablename;
	      $editable{'text'} = $editabletext;
	      push(@editables, \%editable);
	  } else {
	      die "Can't find end of editable region '$editablename'\n";
	  }

     }
    # Append any remaining text
    $text .= $rawtext;

    # Return the template and the list of editables
    return [$text, @editables];
}

sub get_template_name_from_text
{
    my $text = shift;
    my $template_name;
    if ( ($template_name) = ($text =~ m|<\!--\s*#BeginTemplate\s*"([^\"]+)"\s*-->|s) ) {
	$template_name =~ s/^\s+//;
	$template_name =~ s/\s+$//;
        return $template_name;
    }
    return undef;
}

sub parse_templated_file_text
{
    my $text = shift;
    my $template_name;
    my ($pre,$post);
    if ( ($template_name) = ($text =~ m|<\!--\s*#BeginTemplate\s*"([^\"]+)"\s*-->|sg) ) {
	$template_name =~ s/^\s+//;
	$template_name =~ s/\s+$//;
        $pre = $text;
        $pre =~ s|(<\!--\s*#BeginTemplate\s*"[^\"]+"\s*-->\s*\n?).*$|$1|s;
        $post = $text;
        $post =~ s|^.*(<\!--\s*#EndTemplate\s*-->)|$1|s;
        return ($template_name,$pre,$post);
    }
    return (undef,undef,undef);
}

sub find_template
{
    my $file = shift;
    my $dir;
    foreach $dir (@TEMPLATEDIRS) {
	if (-r "$dir/$file") { return "$dir/$file"; }
    }
    if (-r $file) { return $file; }
    return undef;
}

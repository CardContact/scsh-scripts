#!perl

#
# Convert JavaScript file into html file
#
#

#$template = @ARGV[0];
$template = shift;

print "<!-- #BeginTemplate \"$template\" -->\n";
print "<!-- #BeginEditable \"TITLE\" -->\n";
print "<title>Application - Reference Documentation</title>\n";
print "<!-- #EndEditable -->\n";
print "<!-- #BeginEditable \"BODY\" -->\n";
print "<pre>\n";

while (<>) {
        print $_;
}

print "</pre>\n";
print "<!-- #EndEditable -->\n";
print "<!-- #EndTemplate -->\n";


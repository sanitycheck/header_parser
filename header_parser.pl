#!/usr/bin/perl -w
# Author: Dustin Mallory
# Name: header_parser
# Version: 1.0
# Description: Parses email headers
# CHANGE LOG
# Author             Date                Description
# Dustin Mallory | 9/23/2015 | Parses information in email headers
#
#
# Functionality: Discontinuity between name and email name
#                Received spoofed server
#                Sendmail script detection
#                Received with
#                Received by
#
use warnings;
use strict;
use Config;
use Text::Table; # use Text::Table for table generation
use DateTime::Format::Strptime qw ();
#use Net::XWhois;
#use Socket;
no warnings 'uninitialized';

my %header_information; #create a hash for header information

if (grep /--report/, @ARGV) { #use grep to see if --report has been specified as an arguement
    &report(); #if so activate reporting routine
}
sub main { #main routine
    
    my @time_stamps; #array to store time stamps
#    my @domain_array; #array to store parsed domain addresses
    my %sendmail_hash;
    my %ip_ports_table; #hash table of ip addresses and their cooresponding port mail was sent from
    my @IP_array;
    my $header; #declare variable to store header
    my $header_value; #stores header information
    my $from_name;
    my $from_email;
    open(HEADERS, "<", $ARGV[0])
        or die "File not found!";

    my @records = reverse(<HEADERS>); #reverse the files output to trace emails beginning
    close(HEADERS)
        or die "Error Could not close file!";

    foreach my $record (@records) { #iterate through the reversed output
        if ($record =~ /.*(sendmail\.\w*).*/) {
            $sendmail_hash{$record} = $1;
        }
        if (($record =~ /\[(([0-9]{1,3}\.){3}[0-9]{1,3})\]/) or ($record =~ /\s(([0-9]{1,3}\.){3}[0-9]{1,3})\s/)) {
            push(@IP_array, $1);
        }
        if ($record =~ /From:\s(\w.*?)\s<(.*)>/) {
            $from_name = $1;
            $from_email = $2;
        }
        if ($record =~ /\[(([0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})\]/) { #regex to find out if there are ip's and cooresponding port numbers in records
            $ip_ports_table{$1} = $3; # $1 = ip, $3 = port number (add them to hash table)
        }
#        if ($record =~ /.*(\w*\.[a-z]{1,3})\s/) { # regex to find ip addresses
#            if (not grep(@domain_array, $1)) {
#                push(@domain_array, $1); #if there are any add to array
#            }
#        }
        if ($record =~ /((\w){3,4},\s([0-9]){1,2}\s(\w){3}\s([0-9]){4}\s.*?:.*?:.*)/) { #Date and time regex to find time stamps
            push(@time_stamps, $1); # if there are any add them to time_stamp array
        }
        if ($record =~ /(^[A-Z].*?):\s(.*$)/) { #regex to collect headers and their cooresponding values
            $header = $1;
            $header_value = $2;
            #print "$header: $header_value\n";
            if ($header_information{$header}) { #if the hash table ($header_information) has a value that already exists
                $header_information{$header} = $header_information{$header} . " || " . $header_value; #append that value with bars to separate
            }
            else {
                $header_information{$header} = $header_value; #or else create a brand new entry
            }
        }
    }
    &print_headers(); #runs subroutine to print headers
#    &domain_lookup(@domain_array); #looks up ip addresses
    &validate_return(); #checks if return path is valid or looks suspicious
    &check_timestamps(@time_stamps); #checks timestamps to see if they are valid
    if (%ip_ports_table) { #if anything has been found in the ip_ports_table hash
        &check_port(%ip_ports_table); # check to see if ports are suspicious
    }
    if (%sendmail_hash) {
        &detect_sendmail(%sendmail_hash);
    }
    &check_name($from_name,$from_email);
    &whois_lookup(@IP_array);
    &number_header;
}

sub print_headers{
    my $table = Text::Table->new( #creates a nice neat looking table for output
                                  \'| ', # <---- is a separator
                                  { title => 'Header',
                                    align => 'left',
                                    align_title => 'center'
                                  }, 
                                  \' | ',
                                  { title => 'Header Value',
                                    align => 'left',
                                    align_title => 'left'
                                  },
                                  \' |',
                                );
    foreach my $key (sort(keys(%header_information))) { #sort the header information
        $table->load(
            [$key, $header_information{$key}] #and load it into the table using a foreach loop
        );
    }
    
    print $table->title();
    print $table->rule('-','|');
    print $table->body();
    print $table->body_rule('-','-');
    print "\n";
}

sub check_timestamps {

    my @time_stamps = @_; #time stamps are provided from the main routine
    my @dates; #create a dates array to store parsed dates
    my %flags;
    my $parser = DateTime::Format::Strptime->new( #create a new instance of a date parser
        pattern => '%a, %d %b %Y %H:%M:%S %z', #specify the format
        locale => 'en', # language
        on_error => 'croak', #if given error
    );
    foreach my $time_string (@time_stamps) { # for each time stamp in the array
        push(@dates, $parser->parse_datetime($time_string)); #store the parsed date in the dates array
    }
    
    my $counter = 1; #create counter to help iterate through items higher in the array
    foreach my $time (@dates) {
        if ($dates[$counter] le $time) { #if the date ahead of $time is greater than or equal to $time the time stamp is ok
            $flags{"$time--$dates[$counter]"} = "OK"
        }
        else {
               $flags{"$time--$dates[$counter]"} = "SUSPICIOUS"; #else its suspicious
        }
    $counter++; #add to counter
    }
    my $table = Text::Table->new(
                                  \'| ',
                                  { title => 'Time Stamps',
                                    align => 'left',
                                    align_title => 'center'
                                  },
                                  \' | ',
                                  { title => 'Comparison',
                                    align => 'cemter',
                                    align_title => 'left',
                                  },  
                                  \' | ',
                                  { title => 'Status',
                                    align => 'center',
                                    align_title => 'center'
                                  },
                                  \' |',
                                );
    $counter = 0;
    foreach my $key (keys(%flags)) {
        $table->load(
            [$time_stamps[$counter], $key, $flags{$key}]
        );
    $counter++;
    }
    print $table->title();
    print $table->rule('-','|');
    print $table->body();
    print $table->body_rule('-','-');
    print "\n";

}


sub validate_return {
    my $FROM = $header_information{'From'};
    my $RETURN_PATH = $header_information{'Return-Path'};
    my $PATH_STATUS;
    $FROM =~ /.*<(.*)>/;
    $FROM = $1;
    $RETURN_PATH =~ /<(.*)>/;
    $RETURN_PATH = $1;
    if ($FROM ne $RETURN_PATH) {
        $PATH_STATUS = 'SUSPICIOUS';
    } else { $PATH_STATUS = 'OK' }

    my $table = Text::Table->new(
                                  \'| ',
                                  { title => 'Email',
                                    align => 'left',
                                    align_title => 'center'
                                  },
                                  \' | ',
                                  { title => 'Return Path',
                                    align => 'cemter',
                                    align_title => 'left',
                                  },  
                                  \' | ',
                                  { title => 'Path Status',
                                    align => 'center',
                                    align_title => 'center'
                                  },
                                  \' |',
                                );
    $table->load(
        [$FROM, $RETURN_PATH, $PATH_STATUS]
    );
    print $table->title();
    print $table->rule('-','|');
    print $table->body();
    print $table->body_rule('-','-');
    print "\n";


}

#sub domain_lookup {
#    my @domain_array = @_;
#    my %registrant_hash;
#    my %admin_hash;
#    my %tech_hash;
#    my $whois;
#    my $table = Text::Table->new(
#                                  \'| ',
#                                  { title => 'IP Address',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Name',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Organization',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Street',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'City',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'State/Province',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  }, 
#                                  \' | ',
#                                  { title => 'Postal Code',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Country',
#                                    align => 'left',
#                                     align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Phone #',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Phone Ext.',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },
#                                  \' | ',
#                                  { title => 'Email',
#                                    align => 'left',
#                                    align_title => 'left'
#                                  },   
#                                  \' |',
#                                 );
#
#    foreach my $hostname (@domain_array) {
#        $whois = new Net::XWhois;
#        $whois->lookup( Domain => $hostname );
#        my @whois_responses = $whois->response();
#        foreach my $entry (@whois_responses) {
#            $entry =~ /(.*?):\s(.*$)/;
#            my $field = $1;
#            my $info = $2;
#            
#            if ($field =~ /Registrant/) {
#                if ($registrant_hash{$field}) {
#                    $registrant_hash{$field} = $registrant_hash{$field} . ", " . $info;
#                }
#                else {
#                    $registrant_hash{$field} = $info;
#                }
#            }
#            if ($field =~ /Admin/) {
#                if ($registrant_hash{$field}) {
#                    $registrant_hash{$field} = $registrant_hash{$field} . ", " . $info;
#                }
#                else {
#                    $registrant_hash{$field} = $info;
#                }
#            }
#            if ($field =~ /Tech/) {
#                if ($registrant_hash{$field}) {
#                    $registrant_hash{$field} = $registrant_hash{$field} . ", " . $info;
#                }
#                else {
#                    $registrant_hash{$field} = $info;
#                }
#            }
#
#        }
#    
#      $table->load(
#                  [
#                  $hostname,
#                  $registrant_hash{'Registrant Name'},
#                  $registrant_hash{'Registrant Organization'},
#                  $registrant_hash{'Registrant Street'},
#                  $registrant_hash{'Registrant City'},
#                  $registrant_hash{'Registrant State/Province'},
#                  $registrant_hash{'Registrant Postal Code'},
#                  $registrant_hash{'Registrant Country'},
#                  $registrant_hash{'Registrant Phone'},
#                  $registrant_hash{'Registrant Email'}
#                 ]);
#
#    print "REGISTRANT DETAILS FOR $hostname\n";
#    print $table->title();
#    print $table->rule('-','|');
#    print $table->body();
#    print $table->body_rule('-','-');
#    print "\n\n";
#
#    $table->load([
#                  $hostname,
#                  $registrant_hash{'Admin Name'},
#                  $registrant_hash{'Admin Organization'},
#                  $registrant_hash{'Admin Street'},
#                  $registrant_hash{'Admin City'},
#                  $registrant_hash{'Admin State/Province'},
#                  $registrant_hash{'Admin Postal Code'},
#                  $registrant_hash{'Admin Country'},
#                  $registrant_hash{'Admin Phone'},
#                  $registrant_hash{'Admin Email'}
#                 ]);
#
#    print "ADMIN DETAILS FOR $hostname\n";
#    print $table->title();
#    print $table->rule('-','|');
#    print $table->body();
#    print $table->body_rule('-','-');
#    print "\n\n";
#
#    $table->load([
#                  $hostname,
#                  $registrant_hash{'Tech Name'},
#                  $registrant_hash{'Tech Organization'},
#                  $registrant_hash{'Tech Street'},
#                  $registrant_hash{'Tech City'},
#                  $registrant_hash{'Tech State/Province'},
#                  $registrant_hash{'Tech Postal Code'},
#                  $registrant_hash{'Tech Country'},
#                  $registrant_hash{'Tech Phone'},
#                  $registrant_hash{'Tech Email'}
#                 ]);
#
#    print "TECH DETAILS FOR $hostname\n";
#    print $table->title();
#    print $table->rule('-','|');
#    print $table->body();
#    print $table->body_rule('-','-');
#    print "\n\n";
#   }
#}

sub check_port {
    my %ip_ports_table = @_;
    my $imap = '143';
    my $smtp = '25';
    my $pop3 = '110';
    foreach my $ip (keys(%ip_ports_table)) {
        if (($ip_ports_table{$ip} ne $imap) or ($ip_ports_table{$ip} ne $smtp) or ($ip_ports_table{$ip} ne $pop3)) {
            print "\n\n[!] WARNING: EMAIL WAS SENT THROUGH NON-MAIL SERVICE PORT FROM: $ip:$ip_ports_table{$ip}\n";
        }else {print "\n\n[+] Email ports seem legitimate...\n";}
    }
}  

sub detect_sendmail {
    my %sendmail_hash = @_;
    foreach my $record (keys(%sendmail_hash)) {
        print "[!] SUSPICIOUS: EMAIL WAS SENT USING SENDMAIL SCRIPT: $sendmail_hash{$record}\n";
        print "    RECORD: $record\n\n";
    }
}

sub report {
    my $name = 'Dustin Mallory';
    my $student_num = '10130965';
    my $institution = 'Sir Sandford Fleming College';
    my $prof = 'Bryan Milne';
    my $course = 'Computer Security & Investigations';
    my $date = 'Sept. 25 2015';
    my $table = Text::Table->new(
                                  \'| ',
                                  { title => 'Institution',
                                    align => 'left',
                                    align_title => 'left'
                                  },
                                  \' | ',
                                  { title => 'Course Name',
                                    align => 'left',
                                    align_title => 'left'
                                  }, 
                                  \' | ',
                                  { title => 'Instructor',
                                    align => 'left',
                                    align_title => 'left'
                                  },
                                  \' | ',
                                  { title => 'Student Name',
                                    align => 'left',
                                  },  
                                  \' | ',
                                  { title => 'Student #',
                                    align => 'center',
                                    align_title => 'center'
                                  },
                                  \' | ',
                                  { title => 'Date Due',
                                    align => 'left',
                                    align_title => 'left'
                                  },

                                  \' |',
                                );
    $table->load(
                [$institution,
                 $course,
                 $prof,
                 $name,
                 $student_num,
                 $date
            ]
            );
 
    print $table->title();
    print $table->rule('-','|');
    print $table->body();
    print $table->body_rule('-','-');
    print "\n\n";
}

sub check_name {
    my ($from_name, $from_email) = @_;
    my $counter = 0;
    print "CHECKING NAME: $from_name....\n";
    my @names = split(/ /,$from_name);
    foreach my $name (@names) {
        if ($from_email !~ /$name/i) {
            $counter++;
        }
    }
    if ($counter == 2) {
        print "[!] NAME DISCONTINUITY FOUND IN EMAIL ADDRESS: $from_email\n";
    }
    else { 
        print "[+] $from_name SHARES RELATION TO THE EMAIL ADDRESS: $from_email\n";
    }
}

sub number_header {
    open(HEADERS, "<", $ARGV[0])
        or die "Could not generate numbered header";
    my $counter = 1;
    print "\n======GENERATED NUMBER LINED HEADERS======\n\n";
    foreach my $record (<HEADERS>) {
        print "$counter\t$record";
        $counter++;
    }
    print "\n---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------";
    close(HEADERS);
}

sub whois_lookup{
    my @IP_array = @_;
    if (($Config{osname} eq "darwin") or ($Config{osname} eq "linux")) {
        foreach my $ip (@IP_array) {
            print "\n[+] WHOIS INFORMATION FOR: $ip\n";
            system("whois $ip");
        }
    }
    else {
        print "[!] WHOIS LOOKUP IS NOT SUPPORTED ON $Config{osname} SYSTEMS\n";
        }
    }


&main()


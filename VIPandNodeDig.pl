#!/usr/bin/perl
# VIPandNodeDig.pl - for AIG
# j.willis@f5.com - 1-27-2017

# Note: This script is provided as-is and is not supported by F5 Networks.

use strict;
use warnings;

#------------------------------
# Variables, Arrays, and Hashes
#------------------------------
my ($configFile,$configFH,$poolName,$memberName,$memberPort,$ruleName,$virtualName,$answer,$resolvedName,$addr,$outputFD);
my (%virtuals,%pools,%rules,%resolvedIPs) = ();


#------------------------------
# Main
#------------------------------

if ($ARGV[0]) {
    $configFile = $ARGV[0];
} else {
    print "\nUsage: ./VIPandNodeDig.pl <config file>\n";
    exit;
}

&get_VSPoolsRules;
#&show_VSPoolRule_info;
&csv_Output;

#------------------------------
# Subroutines
#------------------------------

sub get_VSPoolsRules {
    
    open($configFH, $configFile) || die "Unable to open '$configFile': $!\n";
    while ( my $line = <$configFH>) {
        chomp($line);
        $line =~ s/[\r\n]$//;
        $line =~ s/\s+$//;
        
        
        # Get pool info
        if ($line =~ /^ltm pool .* \{/ .. $line =~ /^\}/) {
            if ($line =~ /^ltm pool (?:\/Common\/|)(.*) \{/) {
                $poolName = $1;
                $pools{$poolName}{name} = $poolName;
                
            }
            if ($line =~ /^\s{3,4}members \{/ .. $line =~ /^\s{3,4}\}/) {
                if ($line =~ /^\s{6,8}(?:\/Common\/|)(.*):(.*) \{/) {
                    $memberName = $1;
                    $pools{$poolName}{members}{$memberName}{name} = $memberName;
                    $pools{$poolName}{members}{$memberName}{port} = $2;
                }
                if ($line =~ /^\s{9,12}address (.*)/) {
                    $addr = $1;
                    $pools{$poolName}{members}{$memberName}{addr} = $addr;
                    # we don't want to dig an address we already dug
                    print "\r****** getting reverse lookup info for $addr *************";
                    if ($resolvedIPs{$addr}{resolvedName}) {
                        $pools{$poolName}{members}{$memberName}{resolvedName} = $resolvedIPs{$addr}{resolvedName};
                    } else {
                        $resolvedName = &dig_address($addr);
                        $pools{$poolName}{members}{$memberName}{resolvedName} = $resolvedName;
                        $resolvedIPs{$addr}{resolvedName} = $resolvedName;
                    }
                }
            }
        }

        # Get iRules with pool references
        if ($line =~ /^ltm rule .* \{/ .. $line =~ /^\}/){
            if ($line =~ /^ltm rule (?:\/Common\/|)(.*) \{/) {
                $ruleName = $1;
                $rules{$ruleName}{name} = $ruleName;
            }
            if ($line =~ / pool (.*)/) {
                $poolName = $1;
                $rules{$ruleName}{pools}{$poolName}{name} = $poolName;
                $rules{$ruleName}{hasPool} = 1;
            }
        }

        # Get virtuals and pool references
        if ($line =~ /^ltm virtual .* \{/ .. $line =~ /^\}/) {
            if ($line =~ /^ltm virtual (?:\/Common\/|)(.*) \{/) {
                $virtualName = $1;
                $virtuals{$virtualName}{name} = $virtualName;
            }
            if ($line =~ /^\s{3,4}destination (?:\/Common\/|)(.*):(.*)/) {
                $addr = $1;
                $virtuals{$virtualName}{destAddr} = $addr;
                $virtuals{$virtualName}{destPort} = $2;

                # we don't want to dig an address we already dug
                print "\r****** getting reverse lookup info for $addr *************";
                if ($resolvedIPs{$addr}{resolvedName}) {
                    $virtuals{$virtualName}{resolvedName} = $resolvedIPs{$addr}{resolvedName};
                } else {
                    $resolvedName = &dig_address($addr);
                    $virtuals{$virtualName}{resolvedName} = $resolvedName;
                    $resolvedIPs{$addr}{resolvedName} = $resolvedName;
                }
            }
            if ($line =~ /^\s{3,4}ip-forward/) {
                $virtuals{$virtualName}{isIPForward} = 1;
            }
            if ($line =~ /^\s{3,4}pool (?:\/Common\/|)(.*)/) {
                $poolName = $1;
                $virtuals{$virtualName}{pools}{$poolName}{name} = $poolName;
            }
            if ($line =~ /^\s{3,4}rules \{/ .. $line =~ /^\s{3,4}\}/) {
                if ($line =~ /^\s{6,8}(?:\/Common\/|)(.*)/) {
                    $ruleName = $1;
                    next if (!($rules{$ruleName}{hasPool}));
                    $virtuals{$virtualName}{rules}{$ruleName}{name} = $ruleName;
                    foreach $poolName (sort keys %{$rules{$ruleName}{pools}}){
                        next if (defined($virtuals{$virtualName}{pools}{$poolName}{name}));
                        $virtuals{$virtualName}{pools}{$poolName}{name} = $poolName;
                    }
                }
            }
        }
    }
    close($configFH);
}

sub show_VSPoolRule_info {

    foreach $virtualName (sort keys %virtuals){
        next if ($virtuals{$virtualName}{isIPForward});
        print "\nVirtual: $virtualName - Address: $virtuals{$virtualName}{destAddr} - Port: $virtuals{$virtualName}{destPort} - Resolved Name: $virtuals{$virtualName}{resolvedName}\n";
        foreach $poolName (sort keys %{$virtuals{$virtualName}{pools}}){
            print "  Pool: $poolName\n";
            foreach $memberName (sort keys %{$pools{$poolName}{members}}){
                print "    Member: $memberName - Address: $pools{$poolName}{members}{$memberName}{addr} - Port: $pools{$poolName}{members}{$memberName}{port} - Resolved Name: $pools{$poolName}{members}{$memberName}{resolvedName}\n";
            }
        }
    }

}

sub csv_Output {
    my $csvFile = $configFile . "-output" . ".csv";
    system ("rm -f $csvFile");
    open($outputFD, ">>$csvFile") || die "Unable to open '$csvFile': $!\n";
    print $outputFD "Object-type,Object-name,Object-IP,Object-port,Object-name-resolution\n";
    foreach $virtualName (sort keys %virtuals){
        my $printBuffer = "";
        next if ($virtuals{$virtualName}{isIPForward});
        $printBuffer = $printBuffer . "virtual,$virtualName,$virtuals{$virtualName}{destAddr},$virtuals{$virtualName}{destPort},$virtuals{$virtualName}{resolvedName}\n";
        foreach $poolName (sort keys %{$virtuals{$virtualName}{pools}}){
            foreach $memberName (sort keys %{$pools{$poolName}{members}}){
                $printBuffer = $printBuffer . "pool_pool-member,$poolName,$pools{$poolName}{members}{$memberName}{addr},$pools{$poolName}{members}{$memberName}{port},$pools{$poolName}{members}{$memberName}{resolvedName}\n";
            }
        }
        print $outputFD "$printBuffer\n";
    }
    close($outputFD);
    print "\r****** parsing of config is complete. Output is at $csvFile *************\n";
}

sub dig_address {
    my @digRes =();
    my ($addr) = @_;
    $answer = "none";
    my $digResult = `dig -x $addr`;
    @digRes = split /\n/, $digResult;
    
    foreach my $line (@digRes) {
        if ($line =~ /ANSWER SECTION:|AUTHORITY SECTION:/ .. $line =~ /^$/){
            if ($line =~ /\s+(?:SOA)\s+(.*?)(?:\s+)(?:.*)/) {
                $answer = $1;
            }
            if ($line =~ /\s+(?:PTR)\s+(.*)$/) {
                $answer = $1;
            }
        }
    }
    return($answer);
}
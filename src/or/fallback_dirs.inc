/* Trial fallbacks for 0.2.8.2-alpha with ADDRESS_AND_PORT_STABLE_DAYS = 30
 * This works around an issue where relays post a descriptor without a DirPort
 * when restarted. If these relays stay up, they will have been up for
 * approximately 120 days by the 0.2.8 stable release -- teor */
/* Whitelist & blacklist excluded 1047 of 1070 candidates. */
/*
Fallback Directory Summary
Final Count:  23 (Eligible 23, Usable 23, Target 303 (1518 * 0.200000), Clamped to 500)
*/
/* Ignore low fallback numbers in alpha builds -- teor
#error Fallback Count 23 is too low. Must be at least 100 for diversity. Try adding entries to the whitelist, or setting INCLUDE_UNLISTED_ENTRIES = True. */
/*
Final Weight: 490445 (Eligible 539580)
Max Weight:   43166 (8.801%) (Clamped to 10.000%)
Min Weight:   4310 (0.879%) (Clamped to 0.100%)
Clamped:   49134 (10.018%) Excess Weight, 4 High Weight Fallbacks (17.4%)
*/
/*
Onionoo Source: details Date: 2016-02-18 11:00:00 Version: 3.1
URL: https://onionoo.torproject.org/details?fields=fingerprint%2Cnickname%2Ccontact%2Clast_changed_address_or_port%2Cconsensus_weight%2Cor_addresses%2Cdir_address%2Crecommended_version%2Cflags&flag=V2Dir&type=relay&last_seen_days=-7&first_seen_days=30-
*/
/*
Onionoo Source: uptime Date: 2016-02-18 11:00:00 Version: 3.1
URL: https://onionoo.torproject.org/uptime?first_seen_days=30-&flag=V2Dir&type=relay&last_seen_days=-7
*/
/*
kitten2
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 43166 / 490445 (8.801%)
Consensus Weight: 63600 / 539580 (11.787%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"62.210.124.124:9130 orport=9101 id=2EBD117806EE43C3CC885A8F1E4DC60F207E7D3E"
" ipv6=[2001:bc8:3f23:100::1]:9101"
" weight=43166",
/*
pixelminer
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 43166 / 490445 (8.801%)
Consensus Weight: 55700 / 539580 (10.323%)
Christian Sturm <reezer AT pixelminers dot net> - 1Q3PQJTELv33S1nruGcTUMQ7CuWxXmnjkZ
*/
"81.7.14.246:80 orport=443 id=CE75BF0972ADD52AF8807602374E495C815DB304"
" ipv6=[2a02:180:a:51::dead]:443"
" weight=43166",
/*
fluxe4
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 43166 / 490445 (8.801%)
Consensus Weight: 52000 / 539580 (9.637%)
Sebastian <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
*/
"131.188.40.188:443 orport=80 id=EBE718E1A49EE229071702964F8DB1F318075FF8"
" weight=43166",
/*
tornoderdednl
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 43166 / 490445 (8.801%)
Consensus Weight: 50500 / 539580 (9.359%)
0x4871E82F Thom Wiggers <thom @AT@ RDED POINT NL> BTC 1DLyDFV13zhCWJYHMh5bk5C58yYvpxqxfQ
*/
"178.62.199.226:80 orport=443 id=CBEFF7BA4A4062045133C053F2D70524D8BBE5BE"
" ipv6=[2a03:b0c0:2:d0::b7:5001]:443"
" weight=43166",
/*
kitten1
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 40500 / 490445 (8.258%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"62.210.124.124:9030 orport=9001 id=86E78DD3720C78DA8673182EF96C54B162CD660C"
" ipv6=[2001:bc8:3f23:100::1]:9001"
" weight=40500",
/*
coby
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 27300 / 490445 (5.566%)
c0by <coby AT 127001 dot ovh>
*/
"51.255.33.237:9091 orport=9001 id=A360C21FA87FFA2046D92C17086A6B47E5C68109"
" weight=27300",
/*
fluxe3
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 27000 / 490445 (5.505%)
Sebastian <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
*/
"78.47.18.110:443 orport=80 id=F8D27B163B9247B232A2EEE68DD8B698695C28DE"
" weight=27000",
/*
PedicaboMundi
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 26500 / 490445 (5.403%)
0x43DE8191 - 12LiRiasTEL346ZFjgCh5e3nBexQuvDBTg
*/
"144.76.14.145:110 orport=143 id=14419131033443AE6E21DA82B0D307F7CAE42BDB"
" ipv6=[2a01:4f8:190:9490::dead]:443"
" weight=26500",
/*
bakunin
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 24000 / 490445 (4.894%)
GTor <contact _AT_ gtor _DOT_ org>
*/
"178.16.208.57:80 orport=443 id=92CFD9565B24646CAC2D172D3DB503D69E777B8A"
" ipv6=[2a00:1c20:4089:1234:7825:2c5d:1ecd:c66f]:443"
" weight=24000",
/*
kili
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 22600 / 490445 (4.608%)
0x49CBC553 Joost Rijneveld <joost AT joostrijneveld dot nl>
*/
"178.62.173.203:9030 orport=9001 id=DD85503F2D1F52EF9EAD621E942298F46CD2FC10"
" ipv6=[2a03:b0c0:0:1010::a4:b001]:9001"
" weight=22600",
/*
Unnamed
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 18000 / 490445 (3.670%)
monitor0penmailbox0rg
*/
"217.12.199.208:80 orport=443 id=DF3AED4322B1824BF5539AE54B2D1B38E080FF05"
" weight=18000",
/*
eriador
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 15500 / 490445 (3.160%)
hwertiout695@safe-mail.net
*/
"85.25.138.93:9030 orport=4029 id=6DE61A6F72C1E5418A66BFED80DFB63E4C77668F"
" weight=15500",
/*
Logforme
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 15300 / 490445 (3.120%)
Logforme <m7527 AT abc dot se>
*/
"84.219.173.60:9030 orport=443 id=855BC2DABE24C861CD887DB9B2E950424B49FC34"
" weight=15300",
/*
Unnamed
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 13700 / 490445 (2.793%)
monitor0penmailbox0rg
*/
"217.12.210.214:80 orport=443 id=943C0C6841C1E914B9FCA796C6846620A5AF9BC7"
" weight=13700",
/*
Binnacle
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 13600 / 490445 (2.773%)
starlight dot YYYYqQ at binnacle dot cx
*/
"108.53.208.157:80 orport=443 id=4F0DB7E687FC7C0AE55C8F243DA8B0EB27FBF1F2"
" weight=13600",
/*
Nurnberg02
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 11600 / 490445 (2.365%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"213.239.220.25:22 orport=443 id=BEE2317AE127EB681C5AE1551C1EA0630580638A"
" ipv6=[2a01:4f8:a0:710c::2]:80"
" weight=11600",
/*
kitten3
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 11200 / 490445 (2.284%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"212.47.237.95:9030 orport=9001 id=3F5D8A879C58961BB45A3D26AC41B543B40236D6"
" weight=11200",
/*
Nurnberg03
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 10800 / 490445 (2.202%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"85.10.201.38:22 orport=443 id=F6279A203C1950ACF592322A235647A05BFBCF91"
" ipv6=[2a01:4f8:a0:43cc::2]:80"
" weight=10800",
/*
Nurnberg01
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 10500 / 490445 (2.141%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"213.239.210.204:22 orport=443 id=5BFDECCE9B4A23AE14EC767C5A2C1E10558B00B9"
" ipv6=[2a01:4f8:a0:9474::2]:80"
" weight=10500",
/*
Nurnberg04
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 9600 / 490445 (1.957%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"88.198.38.226:22 orport=443 id=4B9E2C56FB42B891794FE2CD2FCAD08A320CC3BB"
" ipv6=[2a01:4f8:a0:1351::2]:80"
" weight=9600",
/*
wagner
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 8810 / 490445 (1.796%)
Rarely used email <trff914 AT gmail DOT com>
*/
"5.175.233.86:80 orport=443 id=5525D0429BFE5DC4F1B0E9DE47A4CFA169661E33"
" weight=8810",
/*
kitten4
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 6960 / 490445 (1.419%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"212.47.237.95:9130 orport=9101 id=6FB38EB22E57EF7ED5EF00238F6A48E553735D88"
" weight=6960",
/*
TeamTardis
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 4310 / 490445 (0.879%)
Team Tardis <drwho@posteo.is>
*/
"185.100.84.212:80 orport=443 id=330CD3DB6AD266DC70CDB512B036957D03D9BC59"
" ipv6=[2a06:1700:0:7::1]:443"
" weight=4310",

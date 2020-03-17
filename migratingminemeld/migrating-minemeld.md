---
id: migrating-minemeld-guide
title: Migrating Minemeld Nodes to Demisto Integrations
---

This guide will provide a reference on how to manually migrate the functionality of Minemeld nodes to the appropriate Demisto integrations. After reading it, you’ll be well equipped  to make the switch from Minemeld to Demisto.

## Supported Minemeld Node Prototypes


"alienvault.reputation",
"aws.AMAZON",
"aws.CLOUDFRONT",
"aws.EC2",
"aws.ROUTE53",
"aws.ROUTE53_HEALTHCHECKS",
"aws.S3",
"azure.cloudIPs",
"bambenekconsulting.c2_dommasterlist",
"bambenekconsulting.c2_dommasterlist_high",
"bambenekconsulting.c2_ipmasterlist",
"bambenekconsulting.c2_ipmasterlist_high",
"binarydefense.banlist",
"blocklist_de.all",
"blocklist_de.apache",
"blocklist_de.bots",
"blocklist_de.bruteforcelogin",
"blocklist_de.ftp",
"blocklist_de.imap",
"blocklist_de.mail",
"blocklist_de.sip",
"blocklist_de.ssh",
"blocklist_de.strongips",
"bruteforceblocker.blist",
"cloudflare.ipv4",
"dshield.block",
"fastly.ipv4",
"feodotracker.badips",
"feodotracker.ipblocklist",
"malwaredomainlist.ip",
"o365-api.china-any",
"o365-api.china-exchange",
"o365-api.china-sharepoint",
"o365-api.china-skype",
"o365-api.germany-any",
"o365-api.germany-common",
"o365-api.germany-exchange",
"o365-api.germany-sharepoint",
"o365-api.germany-skype",
"o365-api.usgovdod-any",
"o365-api.usgovdod-exchange",
"o365-api.usgovdod-sharepoint",
"o365-api.usgovdod-skype",
"o365-api.usgovgcchigh-any",
"o365-api.usgovgcchigh-exchange",
"o365-api.usgovgcchigh-sharepoint",
"o365-api.usgovgcchigh-skype",
"o365-api.worldwide-any",
"o365-api.worldwide-common",
"o365-api.worldwide-exchange",
"o365-api.worldwide-sharepoint",
"o365-api.worldwide-skype",
"phishme.Intelligence",
"proofpoint.EmergingThreatsDomains",
"proofpoint.EmergingThreatsIPs",
"recordedfuture.DomainRiskList",
"recordedfuture.IPRiskList",
"spamhaus.DROP",
"spamhaus.EDROP",
"sslabusech.ipblacklist",
"tor.exit_addresses",


## Unsupported Minemeld Node Prototypes

"ETOpen.blockIPs",
"ETOpen.compromisedIPs",
"anomali.opticAPI",
"auscert.1day_combo",
"auscert.1day_malware",
"auscert.1day_phishing",
"auscert.7days_combo",
"auscert.7days_malware",
"auscert.7days_phishing",
"autofocus.artifactsMiner",
"autofocus.artifactsOutput",
"autofocus.exportList",
"autofocus.indicatorStoreMiner",
"autofocus.indicatorStoreOutput",
"autofocus.samplesMiner",
"badips.blocklist_any_3_2weeks",
"blocklist_de.ircbot",
"blocklist_net_ua.ipset",
"blutmagie.tor_exit_nodes",
"blutmagie.tor_nodes",
"cif.Feed",
"dhs.AIS",
"dhs.CISCP",
"google.GCENetBlocks",
"google.netBlocks",
"greensnow.IP",
"hailataxii.guest_Abuse_ch",
"hailataxii.guest_CyberCrime_Tracker",
"hailataxii.guest_EmergingThreats_rules",
"hailataxii.guest_Lehigh_edu",
"hailataxii.guest_MalwareDomainList_Hostlist",
"hailataxii.guest_blutmagie_de_torExits",
"hailataxii.guest_dataForLast_7daysOnly",
"hailataxii.guest_dshield_BlockList",
"hailataxii.guest_phishtank_com",
"feodotracker.baddomains",
"feodotracker.domainblocklist",
"itcertpa.DOMAINS",
"itcertpa.IP",
"itcertpa.URLS",
"libraesva.LIBRAESVA_Malware_Domains",
"malc0de.DOMAINS",
"malc0de.IP",
"nothink.SNMP_IPBL",
"nothink.SSH_IPBL",
"nothink.Telnet_IPBL",
"o365-api.feed-no-3rdparty",
"office365-dod.any",
"office365-usdefense.any",
"office365.O365",
"office365.O365ProPlus",
"office365.O365RemoteAnalyzers",
"office365.Teams",
"office365.any",
"office365.crls",
"office365.exchangeOnline",
"office365.exchangeOnlineProtection",
"office365.identity",
"office365.office365Video",
"office365.officeMobile",
"office365.officeOnline",
"office365.officeiPad",
"office365.oneNote",
"office365.planner",
"office365.sharepointOnline",
"office365.skypeBusinessOnline",
"office365.sway",
"office365.yammer",
"openbl.base",
"openbl.base_1days",
"openbl.base_30days",
"openphish.feed",
"ransomwaretracker.CW_C2_DOMBL",
"ransomwaretracker.CW_C2_URLBL",
"ransomwaretracker.CW_PS_DOMBL",
"ransomwaretracker.CW_PS_IPBL",
"ransomwaretracker.LY_C2_DOMBL",
"ransomwaretracker.LY_C2_IPBL",
"ransomwaretracker.LY_DS_URLBL",
"ransomwaretracker.LY_PS_DOMBL",
"ransomwaretracker.LY_PS_IPBL",
"ransomwaretracker.RW_DOMBL",
"ransomwaretracker.RW_IPBL",
"ransomwaretracker.RW_URLBL",
"ransomwaretracker.TC_C2_DOMBL",
"ransomwaretracker.TC_C2_URLBL",
"ransomwaretracker.TC_DS_URLBL",
"ransomwaretracker.TC_PS_DOMBL",
"ransomwaretracker.TC_PS_IPBL",
"ransomwaretracker.TL_C2_DOMBL",
"ransomwaretracker.TL_C2_IPBL",
"ransomwaretracker.TL_PS_DOMBL",
"ransomwaretracker.TL_PS_IPBL",
"sslabusech.dyreblacklist",
"stdlib.aggregatorDomain",
"stdlib.aggregatorEmailAddress",
"stdlib.aggregatorFileName",
"stdlib.aggregatorIPv4Generic",
"stdlib.aggregatorIPv4Inbound",
"stdlib.aggregatorIPv4Outbound",
"stdlib.aggregatorIPv6Simple",
"stdlib.aggregatorMD5",
"stdlib.aggregatorMutex",
"stdlib.aggregatorProcessCommandLine",
"stdlib.aggregatorSHA1",
"stdlib.aggregatorSHA256",
"stdlib.aggregatorURL",
"stdlib.aggregatorUserAgentFragment",
"stdlib.aggregatorWindowsRegistryValue",
"stdlib.dagPusher",

"stdlib.feedGreenWithValue",
"stdlib.feedHCGreen",
"stdlib.feedHCGreenWithValue",
"stdlib.feedHCRedWithValue",
"stdlib.feedHCWithValue",
"stdlib.feedLCGreen",
"stdlib.feedLCGreenWithValue",
"stdlib.feedLCRedWithValue",
"stdlib.feedLCWithValue",
"stdlib.feedMCGreen",
"stdlib.feedMCGreenWithValue",
"stdlib.feedMCRedWithValue",
"stdlib.feedMCWithValue",
"stdlib.feedRedWithValue",

"stdlib.listDomainGeneric",
"stdlib.listIPv4Generic",
"stdlib.listIPv6Generic",
"stdlib.listURLGeneric",
"stdlib.localDB",
"stdlib.localLogStash",
"stdlib.localSyslog",
"stdlib.taxiiDataFeed",
"surbl.ThreeLevelTLDS",
"surbl.Two_Level_TLDS",
"threatq.exportHC",
"threatq.exportMC",
"urlhaus.URL",
"virustotal.notifications",
"vxvault.URLBL",
"youtubeminer.channelMiner",
"youtubeminer.eevblog",
"zeustracker.baddomains",
"zeustracker.badips"


## Example

Let's look at a specific example to better understand how to migrate a given Minemeld node. If we wanted to migrate the Bambenek feed shown in the Minemeld configuration file as follows,
```
  C2_Bambenek_Consulting_dommasterlist_high:
    inputs: []
    output: true
    prototype: bambenekconsulting.c2_dommasterlist_high
```
There is a node named `C2_Bambenek_Consulting_dommasterlist_high` which uses the prototype `bambenekconsulting.c2_dommasterlist_high`. All of the prototypes that come out of the box can be found in the Minemeld repository on GitHub [here](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/tree/master/prototypes). Listed there are all the files in which all of Minemeld's prototypes can be found. Since the prototype in our example begins with the prefix `bambenekconsulting`, we know the prototype we are lookin for can be found in the [bambenekconsulting.yml](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/blob/master/prototypes/bambenekconsulting.yml) YAML file. In this file, if we look under the `prototypes` key for `c2_dommasterlist_high`, we find the following,
```
    c2_dommasterlist_high:
        author: MineMeld Core Team
        development_status: DEPRECATED
        node_type: miner
        indicator_types:
            - domain
        tags:
            - OSINT
            - ConfidenceHigh
            - ShareLevelGreen
        description: >
            High Confidence Master Feed of known, active and non-sinkholed C&Cs domain names
        class: minemeld.ft.csv.CSVFT
        config:
            url: http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt
            ignore_regex: '^#'
            age_out:
                default: null
                sudden_death: true
                interval: 1800
            fieldnames:
                - indicator
                - bambenekconsulting_description
                - bambenekconsulting_date
                - bambenekconsulting_info
            attributes:
                type: domain
                confidence: 90
                share_level: green
            source_name: bambenekconsulting.c2_dommasterlist_high
```
The attributes that we need to look at currently for configuring an instance of Cortex XSOAR's Bambenek Feed integration correctly are under the `config` key. Let's look at the Bambenek integration and see how to take these attributes from the Minemeld prototype and translate them to Cortex XSOAR. As shown in the picture below, if we do a search for 'bambenek', the _Bambenek Consulting Feed_ integration appears.

<img width="758" src="./search-bambenek.png"></img>

Wonderful! Let's configure an instance.


## AWS Feed Example

Let's look at a specific example to better understand how to migrate a given Minemeld node. If we wanted to migrate the AWS feed shown in the Minemeld configuration file as follows,
```
  allow-ip_aws_cloudfront:
    inputs: []
    output: true
    prototype: aws.CLOUDFRONT
```
There is a node named `allow-ip_aws_cloudfront` which uses the prototype `aws.CLOUDFRONT`. All of the prototypes that come out of the box can be found in the Minemeld repository on GitHub [here](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/tree/master/prototypes). Listed there are all the files in which all of Minemeld's prototypes can be found. Since the prototype in our example begins with the prefix `aws`, we know the prototype we are lookin for can be found in the [aws.yml](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/blob/master/prototypes/aws.yml) YAML file. In this file, if we look under the `prototypes` key for `CLOUDFRONT`, we find the following,
```
    CLOUDFRONT:
        author: MineMeld Core Team
        development_status: STABLE
        description: CLOUDFRONT ranges
        node_type: miner
        indicator_types:
            - IPv4
        tags:
            - ConfidenceHigh
            - ShareLevelGreen
        class: minemeld.ft.json.SimpleJSON
        config:
            source_name: aws.CLOUDFRONT
            url: https://ip-ranges.amazonaws.com/ip-ranges.json
            extractor: "prefixes[?service=='CLOUDFRONT']"
            prefix: aws
            indicator: ip_prefix
            fields:
                - region
                - service
            age_out:
                default: null
                sudden_death: true
                interval: 257
            attributes:
                type: IPv4
                confidence: 100
                share_level: green
```
The attributes that we need to look at currently for configuring an instance of Cortex XSOAR's AWS Feed integration correctly are under the `config` key. Let's look at the AWS Feed integration and see how to take these attributes from the Minemeld prototype and translate them to Cortex XSOAR. As shown in the picture below, if we do a search for 'aws feed', the _AWS Feed_ integration appears.

<img width="758" src="./search-aws-feed.png"></img>

Wonderful! Let's configure an instance.

<img src="./aws-feed-configuration-1.png"></img>

As you can see in the image above, Cortex XSOAR provides default values for many of the configuration parameters as determined by the source of the feed. To configure the integration instance to fetch from the same source as the Minemeld node we are migrating from, we only need to update a single parameter. In this particular case, we only need to click the `Sub-Feeds` dropdown menu and click `CLOUDFRONT`. 

<img src="./aws-feed-configuration-2.png"></img>

Notice that there is also a multi-select parameter, `Regions`, which we could use if we wanted to filter indicators returned by this `AWS Feed` integration instance by their associated region data field. Since, in our case, we are content to return indicators from all regions, we do not need to adjust this parameter. And walla, as easy as that, we've finished configuring an instance. Let's make sure that everything is working properly by clicking the `Test` button at the bottom of the configuration panel. If everything is working as expected, a green 'Success!' message should appear at the bottom of the configuration panel as shown in the picture below.

<img src="./aws-feed-configuration-3.png"></img>

Click `Done` at the bottom right of the configuration panel and you're all done!


## AWS Feed Continued

As you may have noticed when configuring the `AWS Feed` instance to pull indicators from `CLOUDFRONT`, there were additional sub-feeds that you were able to select. So, if it were the case that your Minemeld configuration contained multiple nodes, as shown below, whose prototypes were prefixed with `aws`, there are two options for configuring these additional AWS feeds in Cortex XSOAR.
```
  allow-ip_aws_cloudfront:
    inputs: []
    output: true
    prototype: aws.CLOUDFRONT
  allow-ip_aws_ec2:
    inputs: []
    output: true
    prototype: aws.EC2
  allow-ip_aws_s3:
    inputs: []
    output: true
    prototype: aws.S3
```
Let's see what we could do now if we wanted to configure the `allow-ip_aws_ec2` Minemeld node, whose prototype is `aws.EC2`, in Cortex XSOAR. In the case that we want to leave the parameter values for fetching from this feed source the same as what we had for fetching indicators from `CLOUDFRONT`, then there is no need to even create a new instance. Click the cog next to our previously configured instance.

<img src="./aws-feed-cog.png"></img>

In the dropdown menu for the `Sub-Feeds` multi-select field, click `EC2`. 

<img src="./aws-feed-configuration-4.png"></img><img src="./aws-feed-configuration-5.png"></img>

Now, both `CLOUDFRONT` and `EC2` are selected for this instance. Click `Done` and this `AWS Feed` integration instance will now fetch indicators from AWS's `CLOUDFRONT`  _and_ `EC2` feeds.

In the case that we wanted to configure an instance of the `AWS Feed` integration to fetch from AWS's `EC2` feed _but_ we wanted it configured for different regions than the instance fetching from the `CLOUDFRONT` feed, then we would simply configure a new, separate instance of the `AWS Feed` as described in the [AWS Feed Example](#aws-feed-example) section.

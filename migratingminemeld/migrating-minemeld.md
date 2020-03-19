---
id: migrating-minemeld-guide
title: Migrating Minemeld Nodes to Cortex XSOAR Integrations
---

This guide will provide a reference on how to manually migrate the functionality of Minemeld nodes to the appropriate Cortex XSOAR integrations. After reading it, you’ll be well equipped  to make the switch from Minemeld to Cortex XSOAR.

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
There is a node named `C2_Bambenek_Consulting_dommasterlist_high` which uses the prototype `bambenekconsulting.c2_dommasterlist_high`. All of the prototypes that come out of the box can be found in the Minemeld repository on GitHub [here](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/tree/master/prototypes). Listed there are all the files in which all of Minemeld's prototypes can be found. Since the prototype in our example begins with the prefix `bambenekconsulting`, we know the prototype we are looking for can be found in the [bambenekconsulting.yml](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/blob/master/prototypes/bambenekconsulting.yml) YAML file. In this file, if we look under the `prototypes` key for `c2_dommasterlist_high`, we find the following,
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
The attributes that we need to look at currently for configuring an instance of Cortex XSOAR's Bambenek Feed integration correctly are under the `config` key. Let's look at the Bambenek integration and see how to take these attributes from the Minemeld prototype and translate them to Cortex XSOAR. As shown in the screenshot below, if we do a search for 'bambenek', the _Bambenek Consulting Feed_ integration appears.

<img width="758" src="./search-bambenek.png"></img>

Let's configure an instance.


## AWS Feed Example

Let's look at a specific example to better understand how to migrate a given Minemeld node. If we wanted to migrate the AWS feed shown in the Minemeld configuration file as follows,
```
  allow-ip_aws_cloudfront:
    inputs: []
    output: true
    prototype: aws.CLOUDFRONT
```
There is a node named `allow-ip_aws_cloudfront` which uses the prototype `aws.CLOUDFRONT`. The `aws` prototypes appear in the AutoFocus-hosted Minemeld UI as in the following screenshot.

<img src="./mm-aws-prototypes.png"></img>

If we click on the `aws.CLOUDFRONT` prototype, we are presented with more details about it. The attributes that we need to look at currently for configuring an instance of Cortex XSOAR's AWS Feed integration correctly are under the `config` key.

<img src="./mm-aws-cloudfront-prototype.png"></img>

Alternatively, we can also find all of this information in the Minemeld GitHub repository. All of the prototypes that come out of the box can be found in the Minemeld repository on GitHub [here](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/tree/master/prototypes). Listed there are all the files in which all of Minemeld's prototypes can be found. Since the prototype in our example begins with the prefix `aws`, we know the prototype we are looking for can be found in the [aws.yml](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/blob/master/prototypes/aws.yml) YAML file. In this file, if we look under the `prototypes` key for `CLOUDFRONT`, we find the following,
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

Let's look at the AWS Feed integration and see how to take these attributes from the Minemeld prototype and translate them to Cortex XSOAR. As shown in the screenshot below, if we do a search for 'aws feed', the _AWS Feed_ integration appears.

<img width="758" src="./search-aws-feed.png"></img>

Let's configure an instance.

<img src="./aws-feed-configuration-1.png"></img>

As you can see in the screenshot above, Cortex XSOAR provides default values for many of the configuration parameters as determined by the source of the feed. To configure the integration instance to fetch from the same source as the Minemeld node we are migrating from, we only need to update a single parameter. In this particular case, we only need to click the `Sub-Feeds` dropdown menu and click `CLOUDFRONT`. 

<img src="./aws-feed-configuration-2.png"></img>

Notice that there is also a multi-select parameter, `Regions`, which we could use if we wanted to filter indicators returned by this `AWS Feed` integration instance by their associated region data field. Since, in our case, we are content to return indicators from all regions, we do not need to adjust this parameter. And as easy as that, we've finished configuring an instance. Let's make sure that everything is working properly by clicking the `Test` button at the bottom of the configuration panel. If everything is working as expected, a green 'Success!' message should appear at the bottom of the configuration panel as shown in the screenshot below.

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


## Office 365 Feed Example

Let's say we wanted to migrate this sample Office 365 node shown from a Minemeld configuration,
```
  allow-multi_o365-worldwide-any:
    inputs: []
    output: true
    prototype: o365-api.worldwide-any
```
There is a node named `allow-multi_o365-worldwide-any` which uses the prototype `o365-api.worldwide-any`. The `o365-api` prototypes appear in the AutoFocus-hosted Minemeld UI as in the following screenshot.

<img src="./mm-o365-prototypes.png"></img>

If we click on the `o365-api.worldwide-any` prototype, we are presented with more details about it. The attributes that we need to look at currently for configuring an instance of Cortex XSOAR's Office 365 Feed integration correctly are under the `config` key.

<img src="./mm-o365-worldwide-any-prototype.png"></img>

Alternatively, we can also find all of this information in the Minemeld GitHub repository. All of the prototypes that come out of the box can be found in the Minemeld repository on GitHub [here](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/tree/master/prototypes). Listed there are all the files in which all of Minemeld's prototypes can be found. Since the prototype in our example begins with the prefix `o365-api`, we know the prototype we are looking for can be found in the [o365-api.yml](https://github.com/PaloAltoNetworks/minemeld-node-prototypes/blob/master/prototypes/o365-api.yml) YAML file. In this file, if we look under the `prototypes` key for `worldwide-any`, we find the following,
```
    worldwide-any:
        author: MineMeld Core Team
        development_status: STABLE
        node_type: miner
        indicator_types:
            - URL
            - IPv6
            - IPv4
        tags:
            - ShareLevelGreen
            - ConfidenceHigh
        description: >
            Endpoints for O365, worldwide instance, any service
        class: minemeld.ft.o365.O365API
        config:
            instance: Worldwide
            service_areas: null
            age_out:
                default: null
                sudden_death: true
                interval: 1800
            attributes:
                confidence: 100
                share_level: green
```

Let's look at the Office 365 Feed integration and see how to take these attributes from the Minemeld prototype and translate them to Cortex XSOAR. As shown in the screenshot below, if we do a search for 'office 365 feed', the _Office 365 Feed_ integration appears.

<img src="./search-office-feed.png"></img>

Let's configure an instance.

<img src="./office-feed-configuration-1.png"></img>

As you can see in the screenshot above, Cortex XSOAR provides default values for many of the configuration parameters as determined by the source of the feed. To configure the integration instance to fetch from the same source as the Minemeld node we are migrating from, we do not need to make any adjustments because the default values for the **Regions** and **Services** configuration parameters are *Worldwide* and *All* respectively, which are the values we need to migrate this particular prototype. 

Click `Done` at the bottom right of the configuration panel and you're all set!

Let's explore two other cases.
Let us say you wanted to migrate two other Office 365 prototypes instead of the one previously described. You want to migrate these two nodes from a Minemeld configuration for example,
```yaml
  allow_o365-china-exchange:
    inputs: []
    output: true
    prototype: o365-api.china-exchange
  allow_o365-germany-exchange:
    inputs: []
    output: true
    prototype: o365-api.germany-exchange
```

We can configure one instance of the _Office 365 Feed_ integration with **Regions** set to *China* and *Germany* and **Services** set to *Exchange*, as shown in the following screenshot.

<img src="./office-feed-configuration-2.png"></img>

In the second case, let's say you wanted to migrate the two nodes from your Minemeld configuration that appear as follows,
```yaml
  allow_o365-china-exchange:
    inputs: []
    output: true
    prototype: o365-api.china-exchange
  allow_o365-germany-skype:
    inputs: []
    output: true
    prototype: o365-api.germany-skype
```

Since these are non-overlapping, we should instead configure two instances of the _Office 365 Feed_ integration. One instance with **Regions** set to *China* and **Services** set to *Exchange* and the other instance with **Regions** set to *Germany* and **Services** set to *Skype* as shown in the screenshots below.

<img src="./office-feed-configuration-3.png"></img><img src="./office-feed-configuration-4.png"></img>


## Indicator Tagging

In the case that we wanted to add a tag to indicators fetched from an integration feed instance we could do this using a Feed-Triggered job as described in the [Threat Intel Management Guide](https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/pdf/cortex/demisto/demisto-threat-intelligence-management-guide/demisto-threat-intelligence-management-guide.pdf).


## Minemeld Prototype to Cortex XSOAR Integration Mapping

The **Parameter Configuration** displays any configuration parameters that need to be specified for the corresponding integration in order for the integration instance to fetch indicators from the same source as the related prototype. The required configuration parameters will be presented as a list of keys and values where the key is the name of the configuration parameter and the value is what the user needs to enter or select. If no parameters are listed, this means that the user does not need to specify any parameter values for that integration instance.

| Prototype | Integration | Parameter Configuration |
| --------- | ----------- | ----------------------- |
| alienvault.reputation | Alienvault Reputation Feed | |
| aws.AMAZON | AWS Feed | **Sub-Feeds**: AMAZON |
| aws.CLOUDFRONT | AWS Feed | **Sub-Feeds**: CLOUDFRONT |
| aws.EC2 | AWS Feed | **Sub-Feeds**: EC2 |
| aws.ROUTE53 | AWS Feed | **Sub-Feeds**: ROUTE53 |
| aws.ROUTE53_HEALTHCHECKS | AWS Feed | **Sub-Feeds**: ROUTE53_HEALTHCHECKS |
| aws.S3 | AWS Feed | **Sub-Feeds**: S3 |
| azure.cloudIPs | Azure Feed | |
| bambenekconsulting.c2_dommasterlist | Bambenek Consulting Feed | **Sub-Feeds**: http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt |
| bambenekconsulting.c2_dommasterlist_high | Bambenek Consulting Feed | **Sub-Feeds**: http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt |
| bambenekconsulting.c2_ipmasterlist | Bambenek Consulting Feed | **Sub-Feeds**: http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt |
| bambenekconsulting.c2_ipmasterlist_high | Bambenek Consulting Feed | **Sub-Feeds**: http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt |
| blocklist_de.all | Blocklist_de Feed | **Sub-Feeds**: all |
| blocklist_de.apache | Blocklist_de Feed | **Sub-Feeds**: apache |
| blocklist_de.bots | Blocklist_de Feed | **Sub-Feeds**: bots |
| blocklist_de.bruteforcelogin | Blocklist_de Feed | **Sub-Feeds**: bruteforcelogin |
| blocklist_de.ftp | Blocklist_de Feed | **Sub-Feeds**: ftp |
| blocklist_de.imap | Blocklist_de Feed | **Sub-Feeds**: imap |
| blocklist_de.mail | Blocklist_de Feed | **Sub-Feeds**: mail |
| blocklist_de.sip | Blocklist_de Feed | **Sub-Feeds**: sip |
| blocklist_de.ssh | Blocklist_de Feed | **Sub-Feeds**: ssh |
| blocklist_de.strongips | Blocklist_de Feed | **Sub-Feeds**: strongips |
| bruteforceblocker.blist | BruteForceBlocker Feed | |
| cloudflare.ipv4 | Cloudflare Feed | **Sub-Feeds**: https://www.cloudflare.com/ips-v4 |
| cloudflare.ipv6 | Cloudflare Feed | **Sub-Feeds**: https://www.cloudflare.com/ips-v6 |
| dshield.block | DShield Feed | |
| fastly.ipv4 | Fastly Feed | |
| feodotracker.badips | Feodo Tracker IP Blocklist Feed | **Feed Source**: Last 30 Days |
| feodotracker.ipblocklist | Feodo Tracker IP Blocklist Feed | **Feed Source**: Currently Active |
| feodotracker.hashes | Feodo Tracker Hashes Feed | |
| malwaredomainlist.ip | Malware Domain List Active IPs Feed | |
| o365-api.china-any | Office 365 Feed | **Regions**: China<br>**Services**: Any |
| o365-api.china-exchange | Office 365 Feed | **Regions**: China<br>**Services**: Exchange |
| o365-api.china-sharepoint | Office 365 Feed | **Regions**: China<br>**Services**: Sharepoint |
| o365-api.china-skype | Office 365 Feed | **Regions**: China<br>**Services**: Skype |
| o365-api.germany-any | Office 365 Feed | **Regions**: Germany<br>**Services**: Any |
| o365-api.germany-common | Office 365 Feed | **Regions**: Germany<br>**Services**: Common |
| o365-api.germany-exchange | Office 365 Feed | **Regions**: Germany<br>**Services**: Exchange |
| o365-api.germany-sharepoint | Office 365 Feed | **Regions**: Germany<br>**Services**: Sharepoint |
| o365-api.germany-skype | Office 365 Feed | **Regions**: Germany<br>**Services**: Skype |
| o365-api.usgovdod-any | Office 365 Feed | **Regions**: USGovDoD<br>**Services**: Any |
| o365-api.usgovdod-exchange | Office 365 Feed | **Regions**: USGovDoD<br>**Services**: Exchange |
| o365-api.usgovdod-sharepoint | Office 365 Feed | **Regions**: USGovDoD<br>**Services**: Sharepoint |
| o365-api.usgovdod-skype | Office 365 Feed | **Regions**: USGovDoD<br>**Services**: Skype |
| o365-api.usgovgcchigh-any | Office 365 Feed | **Regions**: USGovGCCHigh<br>**Services**: Any |
| o365-api.usgovgcchigh-exchange | Office 365 Feed | **Regions**: USGovGCCHigh<br>**Services**: Exchange |
| o365-api.usgovgcchigh-sharepoint | Office 365 Feed | **Regions**: USGovGCCHigh<br>**Services**: Sharepoint |
| o365-api.usgovgcchigh-skype | Office 365 Feed | **Regions**: USGovGCCHigh<br>**Services**: Skype |
| o365-api.worldwide-any | Office 365 Feed | **Regions**: Worldwide<br>**Services**: Any |
| o365-api.worldwide-common | Office 365 Feed | **Regions**: Worldwide<br>**Services**: Common |
| o365-api.worldwide-exchange | Office 365 Feed | **Regions**: Worldwide<br>**Services**: Exchange |
| o365-api.worldwide-sharepoint | Office 365 Feed | **Regions**: Worldwide<br>**Services**: Sharepoint |
| o365-api.worldwide-skype | Office 365 Feed | **Regions**: Worldwide<br>**Services**: Skype |
| phishme.Intelligence | Cofense Feed | **Username**: \<your-cofense-username\><br>**Password**: \<your-cofense-password\> |
| proofpoint.EmergingThreatsDomains | Proofpoint Feed | **Authorization Code**: \<key-from-proofpoint-used-to-access-the-api\><br>**Indicator Reputation**: \<what-reputation-to-assign-indicators-fetched-from-this-feed\><br>**Indicator Type**: domain |
| proofpoint.EmergingThreatsIPs | Proofpoint Feed | **Authorization Code**: \<key-from-proofpoint-used-to-access-the-api\><br>**Indicator Reputation**: \<what-reputation-to-assign-indicators-fetched-from-this-feed\><br>**Indicator Type**: ip |
| recordedfuture.MasterRiskList | Recorded Future RiskList Feed | **Indicator Type**: \<the-type-of-indicator-to-fetch-from-this-feed\><br>**API token**: \<your-recorded-future-api-token\> |
| spamhaus.DROP | Spamhaus Feed | **Sub-Feeds**: https://www.spamhaus.org/drop/drop.txt |
| spamhaus.EDROP | Spamhaus Feed | **Sub-Feeds**: https://www.spamhaus.org/drop/edrop.txt |
| sslabusech.ipblacklist | abuse.ch SSL Blacklist Feed | **Sub-Feeds**: https://sslbl.abuse.ch/blacklist/sslipblacklist.csv |
| tor.exit_addresses | Tor Exit Addresses Feed | |


## Migrating Output Nodes

Outputting indicators with Cortex XSOAR can be performed with two integrations, _Palo Alto Networks PAN-OS EDL Service_ and _Export Indicators Service_. Migrating Minemeld output nodes to Cortex XSOAR is a process that requires looking at the prototype of a given output node, as well as the prototypes of all of the nodes that flow into that output node. We need to do this to understand how to construct the query we will enter when configuring an instance of the _Palo Alto Networks PAN-OS EDL Service_ or _Export Indicators Service_ integration.

Looking at a concrete example will better demonstrate how this is done. Here is an example output node in Minemeld.

<img src="./feed-hc-green-output-node.png"></img>

The first step is to look at the output node's prototype which we can do by clicking the link `stdlib.feedHCGreenWithValue` in the previous screenshot. It appears as follows.

<img src="./feed-hc-green-output-prototype.png"></img>

We see in the `config` section that this prototype filters for indicators whose `confidence` is greater than 75 and whose `share_level` is 'green' - this is the first bit of information we need.
Now let's go back to the node's inputs. We need to explore each one. Our example only has one input node listed - let's explore it by clicking the link there `aggregatorIPv4Inbound-clone-MLB`.

<img src="./ipv4-aggregator-node.png"></img>

Let's see the details of the node's prototype by clicking the prototype linked there - `stdlib.aggregatorIPv4Inbound`.

<img src="./ipv4-aggregator-prototype.png"></img>

We see in the `config` section that this prototype filters for indicators whose `type` is 'IPv4' - let's file this information away for when we configure an integration instance in Cortex XSOAR.
Now if we go back to the aggregator node, we see that it too only has one input node listed. Let's perform the same actions as before and we'll be finished gathering the information we need. Let's click on the input node linked as `exit_addresses-clone-MLB`.

<img src="./exit_addresses-node.png"></img>

Click on the prototype listed there, `tor.exit_addresses`, to see its details.

We know from the table mapping Minemeld prototypes to Cortex XSOAR integrations detailed [above](#Minemeld-Prototype-to-Cortex-XSOAR-Integration-Mapping) that the `tor.exit_addresses` prototype maps to the _Tor Exit Addresses Feed_ integration. And with that, we have all the information we need to move forward. Let's review and gather here the information we collected from looking at the output node we want to migrate, and all the nodes that flow into it.
1. filters for indicators whose `confidence` is greater than 75 and whose `share_level` is 'green'
2. filters for indicators whose `type` is 'IPv4'
3. the `tor.exit_addresses` prototype maps to the _Tor Exit Addresses Feed_ integration

Let's configure an instance of the _Export Indicators Service_ integration using the information we collected to construct the query that defines which indicators are made available. Search for 'export indicators' in your Cortex XSOAR's integrations page as seen in the following screenshot.

<img src="./search-export-indicators.png"></img>

When configuring an instance of this integration, we need to provide an `Indicator Query`. The value entered here uses the same query syntax one would use in the Cortex XSOAR's indicators page to filter and search for specific indicators.

<img src="./export-indicators-configuration-1.png"></img>

So the information we gathered previously, translated to Cortex XSOAR's indicators query syntax would be,
```
type:IP and sourceBrands:"Tor Exit Addresses Feed" and confidence:>75 and trafficlightprotocol:Green
```
Enter that value for the **Indicator Query**.

<img src="./export-indicators-configuration-2.png"></img>

Finish configuring the integration to your desired specifications and press `Done`.
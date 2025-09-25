# تقرير أمان IoT - ٢٦‏/٨‏/٢٠٢٥

**تاريخ الإنشاء:** 2025-08-26 23:33:56

## ملخص التقرير

تم فحص 2 جهاز واكتشاف 92 ثغرة أمنية. مستوى المخاطر: عالي. يتطلب اتخاذ إجراءات فورية.

## الإحصائيات

| المؤشر | العدد |
|---------|-------|
| إجمالي الأجهزة | 2 |
| إجمالي الثغرات | 92 |
| ثغرات حرجة | 1 |
| ثغرات عالية | 6 |
| ثغرات متوسطة | 8 |
| ثغرات منخفضة | 7 |

## تفاصيل الأجهزة والثغرات

### الجهاز: 192.168.8.1

- **نوع الجهاز:** Unknown
- **الشركة المصنعة:** Unknown
- **اسم المضيف:** mobile.router
- **نظام التشغيل:** None
- **إصدار البرنامج الثابت:** None

#### الثغرات المكتشفة (92):

**CVE-2018-11966** - High

Undefined behavior in UE while processing unknown IEI in OTA message in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables in MDM9150, MDM9206, MDM9607, MDM9640, MDM9650, MDM9655, MSM8909W, MSM8996AU, QCS605, SD 210/SD 212/SD 205, SD 425, SD 427, SD 430, SD 435, SD 439 / SD 429, SD 450, SD 625, SD 632, SD 636, SD 650/52, SD 675, SD 712 / SD 710 / SD 670, SD 820, SD 820A, SD 835, SD 845 / SD 850, SD 855, SDA660, SDM439, SDM630, SDM660, SDX20, SM7150, Snapdragon_High_Med_2016, SXR1130

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-2337** - High

While Skipping unknown IES, EMM is reading the buffer even if the no of bytes to read are more than message length which may cause device to shutdown in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables in APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9205, MDM9206, MDM9640, MDM9650, MDM9655, MSM8905, MSM8909, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8976, MSM8996AU, MSM8998, Nicobar, QCM2150, QCS605, QM215, SC8180X, SDA660, SDA845, SDM429, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM670, SDM710, SDM845, SDM850, SDX20, SDX24, SDX55, SM6150, SM7150, SM8150, SM8250, Snapdragon_High_Med_2016, SXR1130, SXR2130

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-14040** - High

Using memory after being freed in qsee due to wrong implementation can lead to unexpected behavior such as execution of unknown code in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8996AU, MSM8998, QCS605, QM215, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM845, SDX20, SDX24, SM8150, SXR1130

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2004-0478** - Unknown

Unknown versions of Mozilla allow remote attackers to cause a denial of service (high CPU/RAM consumption) using Javascript with an infinite loop  that continues to add input to a form, possibly as the result of inserting control characters, as demonstrated using an embedded ctrl-U.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2004-2545** - Unknown

Secure Computing Corporation Sidewinder G2 6.1.0.01 allows remote attackers to cause a denial of service (SMTP proxy failure) via unknown attack vendors involving an "extremely busy network."  NOTE: this might not be a vulnerability because the embedded monitoring sub-system automatically restarts after the failure.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2007-1190** - Unknown

Unspecified vulnerability in the EmbeddedWB Web Browser ActiveX control allows remote attackers to execute arbitrary code via unspecified vectors.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-0711** - Unknown

Unspecified vulnerability in the embedded management console in HP iLO-2 Management Processors (iLO-2 MP), as used in Integrity Servers rx2660, rx3600, and rx6600, and Integrity Blade Server model bl860c, allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-2743** - Unknown

Cross-site scripting (XSS) vulnerability in the embedded web server in Xerox 4110, 4590, and 4595 Copier/Printers allows remote attackers to inject arbitrary web script or HTML via unknown attack vectors.

**التوصية:** Update web interface software. Implement proper input sanitization and output encoding.

---

**CVE-2009-0344** - Unknown

Unspecified vulnerability in the Embedded Lights Out Manager (ELOM) on the Sun Fire X2100 M2 and X2200 M2 x86 platforms before SP/BMC firmware 3.20 allows remote attackers to obtain privileged ELOM login access or execute arbitrary Service Processor (SP) commands via unknown vectors, aka Bug ID 6633175, a different vulnerability than CVE-2007-5717.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-0345** - Unknown

Unspecified vulnerability in the Embedded Lights Out Manager (ELOM) on the Sun Fire X2100 M2 and X2200 M2 x86 platforms before SP/BMC firmware 3.20 allows remote attackers to obtain privileged ELOM login access or execute arbitrary Service Processor (SP) commands via unknown vectors, aka Bug ID 6648082, a different vulnerability than CVE-2007-5717.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-0940** - Unknown

Multiple cross-site request forgery (CSRF) vulnerabilities in the HP Embedded Web Server (EWS) on HP LaserJet Printers, Edgeline Printers, and Digital Senders allow remote attackers to hijack the intranet connectivity of arbitrary users for requests that (1) print documents via unknown vectors, (2) modify the network configuration via a NetIPChange request to hp/device/config_result_YesNo.html/config, or (3) change the password via the Password and ConfirmPassword parameters to hp/device/set_config_password.html/config.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0143** - Unknown

Unspecified vulnerability in the administrative interface in the embedded HTTPS server on the Cisco IronPort Encryption Appliance 6.2.x before 6.2.9.1 and 6.5.x before 6.5.2, and the IronPort PostX MAP before 6.2.9.1, allows remote attackers to read arbitrary files via unknown vectors, aka IronPort Bug 65921.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0144** - Unknown

Unspecified vulnerability in the WebSafe DistributorServlet in the embedded HTTPS server on the Cisco IronPort Encryption Appliance 6.2.x before 6.2.9.1 and 6.5.x before 6.5.2, and the IronPort PostX MAP before 6.2.9.1, allows remote attackers to read arbitrary files via unknown vectors, aka IronPort Bug 65922.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0145** - Unknown

Unspecified vulnerability in the embedded HTTPS server on the Cisco IronPort Encryption Appliance 6.2.x before 6.2.9.1 and 6.5.x before 6.5.2, and the IronPort PostX MAP before 6.2.9.1, allows remote attackers to execute arbitrary code via unknown vectors, aka IronPort Bug 65923.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-3829** - Unknown

Unspecified vulnerability in the Java SE, Java SE Embedded component in Oracle Java SE Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality and integrity via unknown vectors related to Libraries.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5774** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, 6u60 and earlier, 5.0u51 and earlier, and Embedded 7u40 and earlier allows remote attackers to affect integrity via unknown vectors related to Libraries.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5776** - Unknown

Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE Java SE 7u40 and earlier, Java SE 6u60 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect integrity via unknown vectors related to Deployment.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5778** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, 6u60 and earlier, 5.0u51 and earlier, and Embedded 7u40 and earlier allows remote attackers to affect confidentiality via unknown vectors related to 2D.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5780** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality via unknown vectors related to Libraries.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5782** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to 2D.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5783** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality and integrity via unknown vectors related to Swing.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5787** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Deployment, a different vulnerability than CVE-2013-5789, CVE-2013-5824, CVE-2013-5832, and CVE-2013-5852.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5788** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Deployment.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2001-0888** - Unknown

Atmel Firmware 1.3 Wireless Access Point (WAP) allows remote attackers to cause a denial of service via a SNMP request with (1) a community string other than "public" or (2) an unknown OID, which causes the WAP to deny subsequent SNMP requests.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2004-2691** - Unknown

Unspecified vulnerability in 3Com SuperStack 3 4400 switches with firmware version before 3.31 allows remote attackers to cause a denial of service (device reset) via a crafted request to the web management interface.  NOTE: the provenance of this information is unknown; details are obtained from third party reports.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2005-0334** - Unknown

Linksys PSUS4 running firmware 6032 allows remote attackers to cause a denial of service (device crash) via an HTTP POST request containing an unknown parameter without a value.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2005-2552** - Unknown

Unknown vulnerability in HP ProLiant DL585 servers running Integrated Lights Out (ILO) firmware before 1.81 allows attackers to access server controls when the server is "powered down."

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2005-2589** - Unknown

Unknown vulnerability in Linksys WRT54GS wireless router with firmware 4.50.6, with WPA Personal/TKIP authentication enabled, allows remote clients to bypass authentication by connecting without using encryption.

**التوصية:** Update firmware immediately. Implement strong authentication mechanisms and access controls.

---

**CVE-2006-0096** - Unknown

wan/sdla.c in Linux kernel 2.6.x before 2.6.11 and 2.4.x before 2.4.29 does not require the CAP_SYS_RAWIO privilege for an SDLA firmware upgrade, with unknown impact and local attack vectors.  NOTE: further investigation suggests that this issue requires root privileges to exploit, since it is protected by CAP_NET_ADMIN; thus it might not be a vulnerability, although capabilities provide finer distinctions between privilege levels.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-0358** - Unknown

Unspecified vulnerability in the FTP server implementation in HP Jetdirect firmware x.20.nn through x.24.nn allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2007-1542** - Unknown

Unspecified vulnerability in the Cisco IP Phone 7940 and 7960 running firmware before POS8-6-0 allows remote attackers to cause a denial of service via the Remote-Party-ID sipURI field in a SIP INVITE request. NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2007-4018** - Unknown

Citrix Access Gateway Advanced Edition before firmware 4.5.5 allows attackers to redirect users to arbitrary web sites and conduct phishing attacks via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-6003** - Unknown

Cross-site scripting (XSS) vulnerability in cgi/b/ic/connect in the Thomson SpeedTouch 716 with firmware 5.4.0.14 allows remote attackers to inject arbitrary web script or HTML via the url parameter.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update web interface software. Implement proper input sanitization and output encoding.

---

**CVE-2008-3548** - Unknown

Unspecified vulnerability in the Sun Netra T5220 Server with firmware 7.1.3 allows local users to cause a denial of service (panic) via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-4594** - Unknown

Unspecified vulnerability in the SNMPv3 component in Linksys WAP4400N firmware 1.2.14 on the Marvell Semiconductor 88W8361P-BEM1 chipset has unknown impact and attack vectors, probably remote.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-4992** - Unknown

The SPARC hypervisor in Sun System Firmware 6.6.3 through 6.6.5 and 7.1.3 through 7.1.3.e on UltraSPARC T1, T2, and T2+ processors allows logical domain users to access memory in other logical domains via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-5041** - Unknown

Sweex RO002 Router with firmware Ts03-072 has "rdc123" as its default password for the "rdc123" account, which makes it easier for remote attackers to obtain access.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Change all default credentials immediately. Use strong, unique passwords for all accounts.

---

**CVE-2008-5382** - Unknown

Cross-site request forgery (CSRF) vulnerability in I-O DATA DEVICE HDL-F160, HDL-F250, HDL-F300, and HDL-F320 firmware before 1.02 allows remote attackers to (1) change a configuration or (2) delete files as an authenticated user via unknown vectors.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-2073** - Unknown

Cross-site request forgery (CSRF) vulnerability in Linksys WRT160N wireless router hardware 1 and firmware 1.02.2 allows remote attackers to hijack the authentication of other users for unspecified requests via unknown vectors, as demonstrated using administrator privileges and actions.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-7081** - Unknown

userHandler.cgi in RaidSonic ICY BOX NAS firmware 2.3.2.IB.2.RS.1 allows remote attackers to bypass authentication and gain administrator privileges by setting the login parameter to admin. NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update firmware immediately. Implement strong authentication mechanisms and access controls.

---

**CVE-2009-2680** - Unknown

Unspecified vulnerability in the Remote Management Interface (RMI) for MSL Tape Libraries and 1/8 G2 Tape Autoloaders in HP StorageWorks 1/8 G2 Tape Autoloader firmware 2.30 and earlier, MSL2024 Tape Library firmware 4.20 and earlier, MSL4048 Tape Library firmware 6.50 and earlier, and MSL8096 Tape Library firmware 8.90 and earlier allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2004-0477** - Unknown

Unknown vulnerability in 3Com OfficeConnect Remote 812 ADSL Router allows remote attackers to bypass authentication via repeated attempts using any username and password.  NOTE: this identifier was inadvertently re-used for another issue due to a typo; that issue was assigned CVE-2004-0447.  This candidate is ONLY for the ADSL router bypass.

**التوصية:** Update firmware immediately. Implement strong authentication mechanisms and access controls.

---

**CVE-2005-0835** - Unknown

The SNMP service in the Belkin 54G (F5D7130) wireless router allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2006-0119** - Unknown

Multiple unspecified vulnerabilities in IBM Lotus Notes and Domino Server before 6.5.5 have unknown impact and attack vectors, due to "potential security issues" as identified by SPR numbers (1) GPKS6C9J67 in Agents, (2) JGAN6B6TZ3 and (3) KSPR699NBP in the Router, (4) GPKS5YQGPT in Security, or (5) HSAO6BNL6Y in the Web Server. NOTE: vector 3 is related to an issue in NROUTER in IBM Lotus Notes and Domino Server before 6.5.4 FP1, 6.5.5, and 7.0, which allows remote attackers to cause a denial of service (CPU consumption) via a crafted vCal meeting request sent via SMTP (aka SPR# KSPR699NBP).

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2006-2074** - Unknown

Unspecified vulnerability in Juniper Networks JUNOSe E-series routers before 7-1-1 has unknown impact and remote attack vectors related to the DNS "client code," as demonstrated by the OUSPG PROTOS DNS test suite.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-6449** - Unknown

Cross-site request forgery (CSRF) vulnerability in multiple Century Systems routers including XR-410 before 1.6.9, XR-510 before 3.5.3, XR-440 before 1.7.8, and other XR series routers from XR-510 to XR-730 allows remote attackers to modify configuration as the administrator via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-3092** - Unknown

Buffer overflow on the ASUS WL-500W wireless router has unknown impact and remote attack vectors, as demonstrated by a certain module in VulnDisco Pack Professional 8.11.  NOTE: as of 20090903, this disclosure has no actionable information. However, because the VulnDisco Pack author is a reliable researcher, the issue is being assigned a CVE identifier for tracking purposes.

**التوصية:** Update firmware to the latest version. Implement input validation and use memory-safe programming practices.

---

**CVE-2009-3093** - Unknown

Unspecified vulnerability on the ASUS WL-500W wireless router has unknown impact and remote attack vectors, as demonstrated by a certain module in VulnDisco Pack Professional 8.11.  NOTE: as of 20090903, this disclosure has no actionable information. However, because the VulnDisco Pack author is a reliable researcher, the issue is being assigned a CVE identifier for tracking purposes.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0594** - Unknown

Cross-site scripting (XSS) vulnerability in Cisco Router and Security Device Manager (SDM) allows remote attackers to inject arbitrary web script or HTML via unknown vectors, aka Bug ID CSCtb38467.

**التوصية:** Update web interface software. Implement proper input sanitization and output encoding.

---

**CVE-2011-1326** - Unknown

Unspecified vulnerability on the La Fonera+ router with firmware before 1.7.0.1 allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2012-2440** - Unknown

The default configuration of the TP-Link 8840T router enables web-based administration on the WAN interface, which allows remote attackers to establish an HTTP connection and possibly have unspecified other impact via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2012-4712** - Unknown

Moxa EDR-G903 series routers with firmware before 2.11 have a hardcoded account, which allows remote attackers to obtain unspecified device access via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-2340** - Unknown

Unspecified vulnerability on the HP ProCurve JC###A, JC###B, JD###A, JD###B, JE###A, JF###A, JF###B, JF###C, JG###A, 658250-B21, and 658247-B21; HP 3COM routers and switches; and HP H3C routers and switches allows remote attackers to execute arbitrary code or obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-2341** - Unknown

Unspecified vulnerability on the HP ProCurve JC###A, JC###B, JD###A, JD###B, JE###A, JF###A, JF###B, JF###C, JG###A, 658250-B21, and 658247-B21; HP 3COM routers and switches; and HP H3C routers and switches allows remote authenticated users to execute arbitrary code or obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2015-1188** - Unknown

The certificate verification functions in the HNDS service in Swisscom Centro Grande (ADB) DSL routers with firmware before 6.14.00 allows remote attackers to access the management functions via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2022-3332** - Medium

A vulnerability classified as critical has been found in SourceCodester Food Ordering Management System. This affects an unknown part of the file router.php of the component POST Parameter Handler. The manipulation of the argument username leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-209583.

**التوصية:** Update software to patch SQL injection vulnerabilities. Use parameterized queries and input validation.

---

**CVE-2018-25069** - High

A vulnerability classified as critical has been found in Netis Netcore Router. This affects an unknown part. The manipulation leads to use of hard-coded password. It is possible to initiate the attack remotely. The identifier VDB-217593 was assigned to this vulnerability.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2023-0113** - Medium

A vulnerability was found in Netis Netcore Router up to 2.2.6. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to information disclosure. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-217591.

**التوصية:** Update software and review access controls. Ensure sensitive information is properly protected.

---

**CVE-2007-4233** - Unknown

Multiple unspecified vulnerabilities in Camera Life before 2.6 allow attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-6993** - Unknown

Siemens Gigaset WLAN Camera 1.27 has an insecure default password, which allows remote attackers to conduct unauthorized activities. NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Change all default credentials immediately. Use strong, unique passwords for all accounts.

---

**CVE-2010-4027** - Unknown

Unspecified vulnerability in the camera application in HP Palm webOS 1.4.1 allows local users to overwrite arbitrary files via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-25062** - Medium

A vulnerability was found in Sricam IP CCTV Camera and classified as critical. This issue affects some unknown processing of the component Device Viewer. The manipulation leads to memory corruption. An attack has to be approached locally. The exploit has been disclosed to the public and may be used.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-25063** - Medium

A vulnerability was found in Sricam IP CCTV Camera. It has been classified as critical. Affected is an unknown function of the component Device Viewer. The manipulation leads to memory corruption. Local access is required to approach this attack.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-2995** - Medium

A vulnerability was found in NUUO Camera up to 20240319 and classified as problematic. This issue affects some unknown processing of the file /deletefile.php. The manipulation of the argument filename leads to denial of service. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-258197 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2024-3434** - Medium

A vulnerability classified as critical was found in CP Plus Wi-Fi Camera up to 20240401. Affected by this vulnerability is an unknown functionality of the component User Management. The manipulation leads to improper authorization. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-259615. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-5095** - Medium

A vulnerability classified as problematic has been found in Victor Zsviot Camera 8.26.31. This affects an unknown part of the component MQTT Packet Handler. The manipulation leads to denial of service. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-265077 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2024-13892** - Unknown

Smartwares cameras CIP-37210AT and C724IP, as well as others which share the same firmware in versions up to 3.3.0, are vulnerable to command injection. 
During the initialization process, a user has to use a mobile app to provide devices with Access Point credentials. This input is not properly sanitized, what allows for command injection.
The vendor has not replied to reports, so the patching status remains unknown. Newer firmware versions might be vulnerable as well.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-13893** - Unknown

Smartwares cameras CIP-37210AT and C724IP, as well as others which share the same firmware in versions up to 3.3.0, might share same credentials for telnet service. Hash of the password can be retrieved through physical access to SPI connected memory.
For the telnet service to be enabled, the inserted SD card needs to have a folder with a specific name created. 
Two products were tested, but since the vendor has not replied to reports, patching status remains unknown, as well as groups of devices and firmware ranges in which the same password is shared.
 Newer firmware versions might be vulnerable as well.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-13894** - Unknown

Smartwares cameras CIP-37210AT and C724IP, as well as others which share the same firmware in versions up to 3.3.0, are vulnerable to path traversal. 
When an affected device is connected to a mobile app, it opens a port 10000 enabling a user to download pictures shot at specific moments by providing paths to the files. However, the directories to which a user has access are not limited, allowing for path traversal attacks and downloading sensitive information.
The vendor has not replied to reports, so the patching status remains unknown. Newer firmware versions might be vulnerable as well.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-9380** - High

A vulnerability was identified in FNKvision Y215 CCTV Camera 10.194.120.40. Affected by this issue is some unknown functionality of the file /etc/passwd of the component Firmware. Such manipulation leads to hard-coded credentials. Local access is required to approach this attack. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-9381** - Low

A security flaw has been discovered in FNKvision Y215 CCTV Camera 10.194.120.40. This affects an unknown part of the file /tmp/wpa_supplicant.conf. Performing manipulation results in information disclosure. The attack may be carried out on the physical device. The attack's complexity is rated as high. It is indicated that the exploitability is difficult. The exploit has been released to the public and may be exploited. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update software and review access controls. Ensure sensitive information is properly protected.

---

**CVE-2025-9382** - Medium

A weakness has been identified in FNKvision Y215 CCTV Camera 10.194.120.40. This vulnerability affects unknown code of the file s1_rf_test_config of the component Telnet Sevice. Executing manipulation can lead to backdoor. The physical device can be targeted for the attack. This attack is characterized by high complexity. It is stated that the exploitability is difficult. The exploit has been made available to the public and could be exploited. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-4818** - Unknown

Unspecified vulnerability in HP IceWall SSO 8.0 through 10.0, IceWall SSO Agent Option 8.0 through 10.0, IceWall SSO Smart Device Option 10.0, and IceWall File Manager 3.0 through SP4 allows remote attackers to obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-4820** - Unknown

Unspecified vulnerability in HP IceWall SSO 8.0 through 10.0, IceWall SSO Agent Option 8.0 through 10.0, IceWall SSO Smart Device Option 10.0, IceWall SSO SAML2 Agent Option 8.0, IceWall SSO JAVA Agent Library 8.0 through 10.0, IceWall Federation Agent 3.0, and IceWall File Manager 3.0 through SP4 allows remote authenticated users to obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-3124** - Low

A vulnerability classified as problematic has been found in fridgecow smartalarm 1.8.1 on Android. This affects an unknown part of the file androidmanifest.xml of the component Backup File Handler. The manipulation leads to exposure of backup file to an unauthorized control sphere. It is possible to launch the attack on the physical device. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-258867.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-48548** - Critical

The APK file in Cloud Smart Lock v2.0.1 has a leaked a URL that can call an API for binding physical devices. This vulnerability allows attackers to arbitrarily construct a request to use the app to bind to unknown devices by finding a valid serial number via a bruteforce attack.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2023-2754** - High

The Cloudflare WARP client for Windows assigns loopback IPv4 addresses for the DNS Servers, since WARP acts as local DNS server that performs DNS queries in a secure manner, however, if a user is connected to WARP over an IPv6-capable network, te WARP client did not assign loopback IPv6 addresses but Unique Local Addresses, which under certain conditions could point towards unknown devices in the same local network which enables an Attacker to view DNS queries made by the device.




**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2005-2391** - Unknown

Unknown vulnerability in 3Com OfficeConnect Wireless 11g Access Point before 1.03.12 allows remote attackers to obtain sensitive information via the web interface.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-2122** - Unknown

Unspecified vulnerability in the Wireless component in Oracle Application Server 9.0.4.3 has unknown impact and attack vectors, aka AS03.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-4011** - Unknown

Cisco 4100 and 4400, Airespace 4000, and Catalyst 6500 and 3750 Wireless LAN Controller (WLC) software before 3.2 20070727, 4.0 before 20070727, and 4.1 before 4.1.180.0 allows remote attackers to cause a denial of service (traffic amplification or ARP storm) via a crafted unicast ARP request that (1) has a destination MAC address unknown to the Layer-2 infrastructure, aka CSCsj69233; or (2) occurs during Layer-3 roaming across IP subnets, aka CSCsj70841.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-3551** - Unknown

Multiple unspecified vulnerabilities in Sun Java Platform Micro Edition (aka Java ME, J2ME, or mobile Java), as distributed in Sun Wireless Toolkit 2.5.2, allow remote attackers to execute arbitrary code via unknown vectors.  NOTE: as of 20080807, the only disclosure is a vague pre-advisory with no actionable information. However, because it is from a company led by a well-known researcher, it is being assigned a CVE identifier for tracking purposes.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-5662** - Unknown

Multiple buffer overflows in Sun Java Wireless Toolkit (WTK) for CLDC 2.5.2 and earlier allow downloaded programs to execute arbitrary code via unknown vectors.

**التوصية:** Update firmware to the latest version. Implement input validation and use memory-safe programming practices.

---

**CVE-2009-0061** - Unknown

Unspecified vulnerability in the Wireless LAN Controller (WLC) TSEC driver in the Cisco 4400 WLC, Cisco Catalyst 6500 and 7600 Wireless Services Module (WiSM), and Cisco Catalyst 3750 Integrated Wireless LAN Controller with software 4.x before 4.2.176.0 and 5.x before 5.1 allows remote attackers to cause a denial of service (device crash or hang) via unknown IP packets.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2009-0062** - Unknown

Unspecified vulnerability in the Cisco Wireless LAN Controller (WLC), Cisco Catalyst 6500 Wireless Services Module (WiSM), and Cisco Catalyst 3750 Integrated Wireless LAN Controller with software 4.2.173.0 allows remote authenticated users to gain privileges via unknown vectors, as demonstrated by escalation from the (1) Lobby Admin and (2) Local Management User privilege levels.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0835** - Unknown

Unspecified vulnerability in the Wireless component in Oracle Fusion Middleware 10.1.2.3 allows remote attackers to affect integrity via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2012-2017** - Unknown

Unspecified vulnerability on HP Photosmart Wireless e-All-in-One B110, e-All-in-One D110, Plus e-All-in-One B210, eStation All-in-One C510, Ink Advantage e-All-in-One K510, and Premium Fax e-All-in-One C410 printers allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2016-0526** - Unknown

Unspecified vulnerability in the Oracle CRM Technical Foundation component in Oracle E-Business Suite 11.5.10.2, 12.1.3, 12.2.3, 12.2.4, and 12.2.5 allows remote attackers to affect integrity via unknown vectors related to Wireless Framework.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-1612** - Low

A vulnerability was found in Edimax BR-6288ACL 1.30. It has been declared as problematic. This vulnerability affects unknown code of the file wireless5g_basic.asp. The manipulation of the argument SSID leads to cross site scripting. The attack can be initiated remotely. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-1617** - Low

A vulnerability, which was classified as problematic, was found in Netis WF2780 2.1.41925. This affects an unknown part of the component Wireless 2.4G Menu. The manipulation of the argument SSID leads to cross site scripting. It is possible to initiate the attack remotely. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-2213** - Low

A vulnerability was found in Castlenet CBW383G2N up to 20250301. It has been declared as problematic. This vulnerability affects unknown code of the file /wlanPrimaryNetwork.asp of the component Wireless Menu. The manipulation of the argument SSID with the input <img/src/onerror=prompt(8)> leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-3157** - Low

A vulnerability was found in Intelbras WRN 150 1.0.15_pt_ITB01. It has been rated as problematic. This issue affects some unknown processing of the component Wireless Menu. The manipulation of the argument SSID leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. The vendor was contacted early about this issue and explains that the latest version is not affected.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-3764** - Low

** DISPUTED ** A vulnerability classified as problematic has been found in Tuya SDK up to 5.0.x. Affected is an unknown function of the component MQTT Packet Handler. The manipulation leads to denial of service. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The real existence of this vulnerability is still doubted at the moment. Upgrading to version 5.1.0 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-260604. NOTE: The vendor explains that a malicious actor would have to crack TLS first or use a legitimate login to initiate the attack.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

### الجهاز: 192.168.44.1

- **نوع الجهاز:** Unknown
- **الشركة المصنعة:** Unknown
- **اسم المضيف:** _gateway
- **نظام التشغيل:** None
- **إصدار البرنامج الثابت:** None

#### الثغرات المكتشفة (92):

**CVE-2018-11966** - High

Undefined behavior in UE while processing unknown IEI in OTA message in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables in MDM9150, MDM9206, MDM9607, MDM9640, MDM9650, MDM9655, MSM8909W, MSM8996AU, QCS605, SD 210/SD 212/SD 205, SD 425, SD 427, SD 430, SD 435, SD 439 / SD 429, SD 450, SD 625, SD 632, SD 636, SD 650/52, SD 675, SD 712 / SD 710 / SD 670, SD 820, SD 820A, SD 835, SD 845 / SD 850, SD 855, SDA660, SDM439, SDM630, SDM660, SDX20, SM7150, Snapdragon_High_Med_2016, SXR1130

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-2337** - High

While Skipping unknown IES, EMM is reading the buffer even if the no of bytes to read are more than message length which may cause device to shutdown in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables in APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9205, MDM9206, MDM9640, MDM9650, MDM9655, MSM8905, MSM8909, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8976, MSM8996AU, MSM8998, Nicobar, QCM2150, QCS605, QM215, SC8180X, SDA660, SDA845, SDM429, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM670, SDM710, SDM845, SDM850, SDX20, SDX24, SDX55, SM6150, SM7150, SM8150, SM8250, Snapdragon_High_Med_2016, SXR1130, SXR2130

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-14040** - High

Using memory after being freed in qsee due to wrong implementation can lead to unexpected behavior such as execution of unknown code in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8996AU, MSM8998, QCS605, QM215, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM845, SDX20, SDX24, SM8150, SXR1130

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2004-0478** - Unknown

Unknown versions of Mozilla allow remote attackers to cause a denial of service (high CPU/RAM consumption) using Javascript with an infinite loop  that continues to add input to a form, possibly as the result of inserting control characters, as demonstrated using an embedded ctrl-U.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2004-2545** - Unknown

Secure Computing Corporation Sidewinder G2 6.1.0.01 allows remote attackers to cause a denial of service (SMTP proxy failure) via unknown attack vendors involving an "extremely busy network."  NOTE: this might not be a vulnerability because the embedded monitoring sub-system automatically restarts after the failure.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2007-1190** - Unknown

Unspecified vulnerability in the EmbeddedWB Web Browser ActiveX control allows remote attackers to execute arbitrary code via unspecified vectors.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-0711** - Unknown

Unspecified vulnerability in the embedded management console in HP iLO-2 Management Processors (iLO-2 MP), as used in Integrity Servers rx2660, rx3600, and rx6600, and Integrity Blade Server model bl860c, allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-2743** - Unknown

Cross-site scripting (XSS) vulnerability in the embedded web server in Xerox 4110, 4590, and 4595 Copier/Printers allows remote attackers to inject arbitrary web script or HTML via unknown attack vectors.

**التوصية:** Update web interface software. Implement proper input sanitization and output encoding.

---

**CVE-2009-0344** - Unknown

Unspecified vulnerability in the Embedded Lights Out Manager (ELOM) on the Sun Fire X2100 M2 and X2200 M2 x86 platforms before SP/BMC firmware 3.20 allows remote attackers to obtain privileged ELOM login access or execute arbitrary Service Processor (SP) commands via unknown vectors, aka Bug ID 6633175, a different vulnerability than CVE-2007-5717.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-0345** - Unknown

Unspecified vulnerability in the Embedded Lights Out Manager (ELOM) on the Sun Fire X2100 M2 and X2200 M2 x86 platforms before SP/BMC firmware 3.20 allows remote attackers to obtain privileged ELOM login access or execute arbitrary Service Processor (SP) commands via unknown vectors, aka Bug ID 6648082, a different vulnerability than CVE-2007-5717.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-0940** - Unknown

Multiple cross-site request forgery (CSRF) vulnerabilities in the HP Embedded Web Server (EWS) on HP LaserJet Printers, Edgeline Printers, and Digital Senders allow remote attackers to hijack the intranet connectivity of arbitrary users for requests that (1) print documents via unknown vectors, (2) modify the network configuration via a NetIPChange request to hp/device/config_result_YesNo.html/config, or (3) change the password via the Password and ConfirmPassword parameters to hp/device/set_config_password.html/config.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0143** - Unknown

Unspecified vulnerability in the administrative interface in the embedded HTTPS server on the Cisco IronPort Encryption Appliance 6.2.x before 6.2.9.1 and 6.5.x before 6.5.2, and the IronPort PostX MAP before 6.2.9.1, allows remote attackers to read arbitrary files via unknown vectors, aka IronPort Bug 65921.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0144** - Unknown

Unspecified vulnerability in the WebSafe DistributorServlet in the embedded HTTPS server on the Cisco IronPort Encryption Appliance 6.2.x before 6.2.9.1 and 6.5.x before 6.5.2, and the IronPort PostX MAP before 6.2.9.1, allows remote attackers to read arbitrary files via unknown vectors, aka IronPort Bug 65922.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0145** - Unknown

Unspecified vulnerability in the embedded HTTPS server on the Cisco IronPort Encryption Appliance 6.2.x before 6.2.9.1 and 6.5.x before 6.5.2, and the IronPort PostX MAP before 6.2.9.1, allows remote attackers to execute arbitrary code via unknown vectors, aka IronPort Bug 65923.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-3829** - Unknown

Unspecified vulnerability in the Java SE, Java SE Embedded component in Oracle Java SE Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality and integrity via unknown vectors related to Libraries.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5774** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, 6u60 and earlier, 5.0u51 and earlier, and Embedded 7u40 and earlier allows remote attackers to affect integrity via unknown vectors related to Libraries.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5776** - Unknown

Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE Java SE 7u40 and earlier, Java SE 6u60 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect integrity via unknown vectors related to Deployment.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5778** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, 6u60 and earlier, 5.0u51 and earlier, and Embedded 7u40 and earlier allows remote attackers to affect confidentiality via unknown vectors related to 2D.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5780** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality via unknown vectors related to Libraries.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5782** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to 2D.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5783** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality and integrity via unknown vectors related to Swing.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5787** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Deployment, a different vulnerability than CVE-2013-5789, CVE-2013-5824, CVE-2013-5832, and CVE-2013-5852.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-5788** - Unknown

Unspecified vulnerability in Oracle Java SE 7u40 and earlier and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Deployment.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2001-0888** - Unknown

Atmel Firmware 1.3 Wireless Access Point (WAP) allows remote attackers to cause a denial of service via a SNMP request with (1) a community string other than "public" or (2) an unknown OID, which causes the WAP to deny subsequent SNMP requests.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2004-2691** - Unknown

Unspecified vulnerability in 3Com SuperStack 3 4400 switches with firmware version before 3.31 allows remote attackers to cause a denial of service (device reset) via a crafted request to the web management interface.  NOTE: the provenance of this information is unknown; details are obtained from third party reports.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2005-0334** - Unknown

Linksys PSUS4 running firmware 6032 allows remote attackers to cause a denial of service (device crash) via an HTTP POST request containing an unknown parameter without a value.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2005-2552** - Unknown

Unknown vulnerability in HP ProLiant DL585 servers running Integrated Lights Out (ILO) firmware before 1.81 allows attackers to access server controls when the server is "powered down."

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2005-2589** - Unknown

Unknown vulnerability in Linksys WRT54GS wireless router with firmware 4.50.6, with WPA Personal/TKIP authentication enabled, allows remote clients to bypass authentication by connecting without using encryption.

**التوصية:** Update firmware immediately. Implement strong authentication mechanisms and access controls.

---

**CVE-2006-0096** - Unknown

wan/sdla.c in Linux kernel 2.6.x before 2.6.11 and 2.4.x before 2.4.29 does not require the CAP_SYS_RAWIO privilege for an SDLA firmware upgrade, with unknown impact and local attack vectors.  NOTE: further investigation suggests that this issue requires root privileges to exploit, since it is protected by CAP_NET_ADMIN; thus it might not be a vulnerability, although capabilities provide finer distinctions between privilege levels.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-0358** - Unknown

Unspecified vulnerability in the FTP server implementation in HP Jetdirect firmware x.20.nn through x.24.nn allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2007-1542** - Unknown

Unspecified vulnerability in the Cisco IP Phone 7940 and 7960 running firmware before POS8-6-0 allows remote attackers to cause a denial of service via the Remote-Party-ID sipURI field in a SIP INVITE request. NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2007-4018** - Unknown

Citrix Access Gateway Advanced Edition before firmware 4.5.5 allows attackers to redirect users to arbitrary web sites and conduct phishing attacks via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-6003** - Unknown

Cross-site scripting (XSS) vulnerability in cgi/b/ic/connect in the Thomson SpeedTouch 716 with firmware 5.4.0.14 allows remote attackers to inject arbitrary web script or HTML via the url parameter.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update web interface software. Implement proper input sanitization and output encoding.

---

**CVE-2008-3548** - Unknown

Unspecified vulnerability in the Sun Netra T5220 Server with firmware 7.1.3 allows local users to cause a denial of service (panic) via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-4594** - Unknown

Unspecified vulnerability in the SNMPv3 component in Linksys WAP4400N firmware 1.2.14 on the Marvell Semiconductor 88W8361P-BEM1 chipset has unknown impact and attack vectors, probably remote.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-4992** - Unknown

The SPARC hypervisor in Sun System Firmware 6.6.3 through 6.6.5 and 7.1.3 through 7.1.3.e on UltraSPARC T1, T2, and T2+ processors allows logical domain users to access memory in other logical domains via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-5041** - Unknown

Sweex RO002 Router with firmware Ts03-072 has "rdc123" as its default password for the "rdc123" account, which makes it easier for remote attackers to obtain access.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Change all default credentials immediately. Use strong, unique passwords for all accounts.

---

**CVE-2008-5382** - Unknown

Cross-site request forgery (CSRF) vulnerability in I-O DATA DEVICE HDL-F160, HDL-F250, HDL-F300, and HDL-F320 firmware before 1.02 allows remote attackers to (1) change a configuration or (2) delete files as an authenticated user via unknown vectors.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-2073** - Unknown

Cross-site request forgery (CSRF) vulnerability in Linksys WRT160N wireless router hardware 1 and firmware 1.02.2 allows remote attackers to hijack the authentication of other users for unspecified requests via unknown vectors, as demonstrated using administrator privileges and actions.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-7081** - Unknown

userHandler.cgi in RaidSonic ICY BOX NAS firmware 2.3.2.IB.2.RS.1 allows remote attackers to bypass authentication and gain administrator privileges by setting the login parameter to admin. NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Update firmware immediately. Implement strong authentication mechanisms and access controls.

---

**CVE-2009-2680** - Unknown

Unspecified vulnerability in the Remote Management Interface (RMI) for MSL Tape Libraries and 1/8 G2 Tape Autoloaders in HP StorageWorks 1/8 G2 Tape Autoloader firmware 2.30 and earlier, MSL2024 Tape Library firmware 4.20 and earlier, MSL4048 Tape Library firmware 6.50 and earlier, and MSL8096 Tape Library firmware 8.90 and earlier allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2004-0477** - Unknown

Unknown vulnerability in 3Com OfficeConnect Remote 812 ADSL Router allows remote attackers to bypass authentication via repeated attempts using any username and password.  NOTE: this identifier was inadvertently re-used for another issue due to a typo; that issue was assigned CVE-2004-0447.  This candidate is ONLY for the ADSL router bypass.

**التوصية:** Update firmware immediately. Implement strong authentication mechanisms and access controls.

---

**CVE-2005-0835** - Unknown

The SNMP service in the Belkin 54G (F5D7130) wireless router allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2006-0119** - Unknown

Multiple unspecified vulnerabilities in IBM Lotus Notes and Domino Server before 6.5.5 have unknown impact and attack vectors, due to "potential security issues" as identified by SPR numbers (1) GPKS6C9J67 in Agents, (2) JGAN6B6TZ3 and (3) KSPR699NBP in the Router, (4) GPKS5YQGPT in Security, or (5) HSAO6BNL6Y in the Web Server. NOTE: vector 3 is related to an issue in NROUTER in IBM Lotus Notes and Domino Server before 6.5.4 FP1, 6.5.5, and 7.0, which allows remote attackers to cause a denial of service (CPU consumption) via a crafted vCal meeting request sent via SMTP (aka SPR# KSPR699NBP).

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2006-2074** - Unknown

Unspecified vulnerability in Juniper Networks JUNOSe E-series routers before 7-1-1 has unknown impact and remote attack vectors related to the DNS "client code," as demonstrated by the OUSPG PROTOS DNS test suite.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-6449** - Unknown

Cross-site request forgery (CSRF) vulnerability in multiple Century Systems routers including XR-410 before 1.6.9, XR-510 before 3.5.3, XR-440 before 1.7.8, and other XR series routers from XR-510 to XR-730 allows remote attackers to modify configuration as the administrator via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2009-3092** - Unknown

Buffer overflow on the ASUS WL-500W wireless router has unknown impact and remote attack vectors, as demonstrated by a certain module in VulnDisco Pack Professional 8.11.  NOTE: as of 20090903, this disclosure has no actionable information. However, because the VulnDisco Pack author is a reliable researcher, the issue is being assigned a CVE identifier for tracking purposes.

**التوصية:** Update firmware to the latest version. Implement input validation and use memory-safe programming practices.

---

**CVE-2009-3093** - Unknown

Unspecified vulnerability on the ASUS WL-500W wireless router has unknown impact and remote attack vectors, as demonstrated by a certain module in VulnDisco Pack Professional 8.11.  NOTE: as of 20090903, this disclosure has no actionable information. However, because the VulnDisco Pack author is a reliable researcher, the issue is being assigned a CVE identifier for tracking purposes.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0594** - Unknown

Cross-site scripting (XSS) vulnerability in Cisco Router and Security Device Manager (SDM) allows remote attackers to inject arbitrary web script or HTML via unknown vectors, aka Bug ID CSCtb38467.

**التوصية:** Update web interface software. Implement proper input sanitization and output encoding.

---

**CVE-2011-1326** - Unknown

Unspecified vulnerability on the La Fonera+ router with firmware before 1.7.0.1 allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2012-2440** - Unknown

The default configuration of the TP-Link 8840T router enables web-based administration on the WAN interface, which allows remote attackers to establish an HTTP connection and possibly have unspecified other impact via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2012-4712** - Unknown

Moxa EDR-G903 series routers with firmware before 2.11 have a hardcoded account, which allows remote attackers to obtain unspecified device access via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-2340** - Unknown

Unspecified vulnerability on the HP ProCurve JC###A, JC###B, JD###A, JD###B, JE###A, JF###A, JF###B, JF###C, JG###A, 658250-B21, and 658247-B21; HP 3COM routers and switches; and HP H3C routers and switches allows remote attackers to execute arbitrary code or obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-2341** - Unknown

Unspecified vulnerability on the HP ProCurve JC###A, JC###B, JD###A, JD###B, JE###A, JF###A, JF###B, JF###C, JG###A, 658250-B21, and 658247-B21; HP 3COM routers and switches; and HP H3C routers and switches allows remote authenticated users to execute arbitrary code or obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2015-1188** - Unknown

The certificate verification functions in the HNDS service in Swisscom Centro Grande (ADB) DSL routers with firmware before 6.14.00 allows remote attackers to access the management functions via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2022-3332** - Medium

A vulnerability classified as critical has been found in SourceCodester Food Ordering Management System. This affects an unknown part of the file router.php of the component POST Parameter Handler. The manipulation of the argument username leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-209583.

**التوصية:** Update software to patch SQL injection vulnerabilities. Use parameterized queries and input validation.

---

**CVE-2018-25069** - High

A vulnerability classified as critical has been found in Netis Netcore Router. This affects an unknown part. The manipulation leads to use of hard-coded password. It is possible to initiate the attack remotely. The identifier VDB-217593 was assigned to this vulnerability.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2023-0113** - Medium

A vulnerability was found in Netis Netcore Router up to 2.2.6. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to information disclosure. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-217591.

**التوصية:** Update software and review access controls. Ensure sensitive information is properly protected.

---

**CVE-2007-4233** - Unknown

Multiple unspecified vulnerabilities in Camera Life before 2.6 allow attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-6993** - Unknown

Siemens Gigaset WLAN Camera 1.27 has an insecure default password, which allows remote attackers to conduct unauthorized activities. NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

**التوصية:** Change all default credentials immediately. Use strong, unique passwords for all accounts.

---

**CVE-2010-4027** - Unknown

Unspecified vulnerability in the camera application in HP Palm webOS 1.4.1 allows local users to overwrite arbitrary files via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-25062** - Medium

A vulnerability was found in Sricam IP CCTV Camera and classified as critical. This issue affects some unknown processing of the component Device Viewer. The manipulation leads to memory corruption. An attack has to be approached locally. The exploit has been disclosed to the public and may be used.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2019-25063** - Medium

A vulnerability was found in Sricam IP CCTV Camera. It has been classified as critical. Affected is an unknown function of the component Device Viewer. The manipulation leads to memory corruption. Local access is required to approach this attack.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-2995** - Medium

A vulnerability was found in NUUO Camera up to 20240319 and classified as problematic. This issue affects some unknown processing of the file /deletefile.php. The manipulation of the argument filename leads to denial of service. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-258197 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2024-3434** - Medium

A vulnerability classified as critical was found in CP Plus Wi-Fi Camera up to 20240401. Affected by this vulnerability is an unknown functionality of the component User Management. The manipulation leads to improper authorization. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-259615. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-5095** - Medium

A vulnerability classified as problematic has been found in Victor Zsviot Camera 8.26.31. This affects an unknown part of the component MQTT Packet Handler. The manipulation leads to denial of service. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-265077 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2024-13892** - Unknown

Smartwares cameras CIP-37210AT and C724IP, as well as others which share the same firmware in versions up to 3.3.0, are vulnerable to command injection. 
During the initialization process, a user has to use a mobile app to provide devices with Access Point credentials. This input is not properly sanitized, what allows for command injection.
The vendor has not replied to reports, so the patching status remains unknown. Newer firmware versions might be vulnerable as well.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-13893** - Unknown

Smartwares cameras CIP-37210AT and C724IP, as well as others which share the same firmware in versions up to 3.3.0, might share same credentials for telnet service. Hash of the password can be retrieved through physical access to SPI connected memory.
For the telnet service to be enabled, the inserted SD card needs to have a folder with a specific name created. 
Two products were tested, but since the vendor has not replied to reports, patching status remains unknown, as well as groups of devices and firmware ranges in which the same password is shared.
 Newer firmware versions might be vulnerable as well.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-13894** - Unknown

Smartwares cameras CIP-37210AT and C724IP, as well as others which share the same firmware in versions up to 3.3.0, are vulnerable to path traversal. 
When an affected device is connected to a mobile app, it opens a port 10000 enabling a user to download pictures shot at specific moments by providing paths to the files. However, the directories to which a user has access are not limited, allowing for path traversal attacks and downloading sensitive information.
The vendor has not replied to reports, so the patching status remains unknown. Newer firmware versions might be vulnerable as well.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-9380** - High

A vulnerability was identified in FNKvision Y215 CCTV Camera 10.194.120.40. Affected by this issue is some unknown functionality of the file /etc/passwd of the component Firmware. Such manipulation leads to hard-coded credentials. Local access is required to approach this attack. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-9381** - Low

A security flaw has been discovered in FNKvision Y215 CCTV Camera 10.194.120.40. This affects an unknown part of the file /tmp/wpa_supplicant.conf. Performing manipulation results in information disclosure. The attack may be carried out on the physical device. The attack's complexity is rated as high. It is indicated that the exploitability is difficult. The exploit has been released to the public and may be exploited. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update software and review access controls. Ensure sensitive information is properly protected.

---

**CVE-2025-9382** - Medium

A weakness has been identified in FNKvision Y215 CCTV Camera 10.194.120.40. This vulnerability affects unknown code of the file s1_rf_test_config of the component Telnet Sevice. Executing manipulation can lead to backdoor. The physical device can be targeted for the attack. This attack is characterized by high complexity. It is stated that the exploitability is difficult. The exploit has been made available to the public and could be exploited. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-4818** - Unknown

Unspecified vulnerability in HP IceWall SSO 8.0 through 10.0, IceWall SSO Agent Option 8.0 through 10.0, IceWall SSO Smart Device Option 10.0, and IceWall File Manager 3.0 through SP4 allows remote attackers to obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2013-4820** - Unknown

Unspecified vulnerability in HP IceWall SSO 8.0 through 10.0, IceWall SSO Agent Option 8.0 through 10.0, IceWall SSO Smart Device Option 10.0, IceWall SSO SAML2 Agent Option 8.0, IceWall SSO JAVA Agent Library 8.0 through 10.0, IceWall Federation Agent 3.0, and IceWall File Manager 3.0 through SP4 allows remote authenticated users to obtain sensitive information via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-3124** - Low

A vulnerability classified as problematic has been found in fridgecow smartalarm 1.8.1 on Android. This affects an unknown part of the file androidmanifest.xml of the component Backup File Handler. The manipulation leads to exposure of backup file to an unauthorized control sphere. It is possible to launch the attack on the physical device. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-258867.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-48548** - Critical

The APK file in Cloud Smart Lock v2.0.1 has a leaked a URL that can call an API for binding physical devices. This vulnerability allows attackers to arbitrarily construct a request to use the app to bind to unknown devices by finding a valid serial number via a bruteforce attack.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2023-2754** - High

The Cloudflare WARP client for Windows assigns loopback IPv4 addresses for the DNS Servers, since WARP acts as local DNS server that performs DNS queries in a secure manner, however, if a user is connected to WARP over an IPv6-capable network, te WARP client did not assign loopback IPv6 addresses but Unique Local Addresses, which under certain conditions could point towards unknown devices in the same local network which enables an Attacker to view DNS queries made by the device.




**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2005-2391** - Unknown

Unknown vulnerability in 3Com OfficeConnect Wireless 11g Access Point before 1.03.12 allows remote attackers to obtain sensitive information via the web interface.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-2122** - Unknown

Unspecified vulnerability in the Wireless component in Oracle Application Server 9.0.4.3 has unknown impact and attack vectors, aka AS03.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2007-4011** - Unknown

Cisco 4100 and 4400, Airespace 4000, and Catalyst 6500 and 3750 Wireless LAN Controller (WLC) software before 3.2 20070727, 4.0 before 20070727, and 4.1 before 4.1.180.0 allows remote attackers to cause a denial of service (traffic amplification or ARP storm) via a crafted unicast ARP request that (1) has a destination MAC address unknown to the Layer-2 infrastructure, aka CSCsj69233; or (2) occurs during Layer-3 roaming across IP subnets, aka CSCsj70841.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2008-3551** - Unknown

Multiple unspecified vulnerabilities in Sun Java Platform Micro Edition (aka Java ME, J2ME, or mobile Java), as distributed in Sun Wireless Toolkit 2.5.2, allow remote attackers to execute arbitrary code via unknown vectors.  NOTE: as of 20080807, the only disclosure is a vague pre-advisory with no actionable information. However, because it is from a company led by a well-known researcher, it is being assigned a CVE identifier for tracking purposes.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2008-5662** - Unknown

Multiple buffer overflows in Sun Java Wireless Toolkit (WTK) for CLDC 2.5.2 and earlier allow downloaded programs to execute arbitrary code via unknown vectors.

**التوصية:** Update firmware to the latest version. Implement input validation and use memory-safe programming practices.

---

**CVE-2009-0061** - Unknown

Unspecified vulnerability in the Wireless LAN Controller (WLC) TSEC driver in the Cisco 4400 WLC, Cisco Catalyst 6500 and 7600 Wireless Services Module (WiSM), and Cisco Catalyst 3750 Integrated Wireless LAN Controller with software 4.x before 4.2.176.0 and 5.x before 5.1 allows remote attackers to cause a denial of service (device crash or hang) via unknown IP packets.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2009-0062** - Unknown

Unspecified vulnerability in the Cisco Wireless LAN Controller (WLC), Cisco Catalyst 6500 Wireless Services Module (WiSM), and Cisco Catalyst 3750 Integrated Wireless LAN Controller with software 4.2.173.0 allows remote authenticated users to gain privileges via unknown vectors, as demonstrated by escalation from the (1) Lobby Admin and (2) Local Management User privilege levels.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2010-0835** - Unknown

Unspecified vulnerability in the Wireless component in Oracle Fusion Middleware 10.1.2.3 allows remote attackers to affect integrity via unknown vectors.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2012-2017** - Unknown

Unspecified vulnerability on HP Photosmart Wireless e-All-in-One B110, e-All-in-One D110, Plus e-All-in-One B210, eStation All-in-One C510, Ink Advantage e-All-in-One K510, and Premium Fax e-All-in-One C410 printers allows remote attackers to cause a denial of service via unknown vectors.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

**CVE-2016-0526** - Unknown

Unspecified vulnerability in the Oracle CRM Technical Foundation component in Oracle E-Business Suite 11.5.10.2, 12.1.3, 12.2.3, 12.2.4, and 12.2.5 allows remote attackers to affect integrity via unknown vectors related to Wireless Framework.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-1612** - Low

A vulnerability was found in Edimax BR-6288ACL 1.30. It has been declared as problematic. This vulnerability affects unknown code of the file wireless5g_basic.asp. The manipulation of the argument SSID leads to cross site scripting. The attack can be initiated remotely. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-1617** - Low

A vulnerability, which was classified as problematic, was found in Netis WF2780 2.1.41925. This affects an unknown part of the component Wireless 2.4G Menu. The manipulation of the argument SSID leads to cross site scripting. It is possible to initiate the attack remotely. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-2213** - Low

A vulnerability was found in Castlenet CBW383G2N up to 20250301. It has been declared as problematic. This vulnerability affects unknown code of the file /wlanPrimaryNetwork.asp of the component Wireless Menu. The manipulation of the argument SSID with the input <img/src/onerror=prompt(8)> leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. The vendor was contacted early about this disclosure but did not respond in any way.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2025-3157** - Low

A vulnerability was found in Intelbras WRN 150 1.0.15_pt_ITB01. It has been rated as problematic. This issue affects some unknown processing of the component Wireless Menu. The manipulation of the argument SSID leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. The vendor was contacted early about this issue and explains that the latest version is not affected.

**التوصية:** Update device firmware to the latest version. Review security configuration and apply vendor security patches.

---

**CVE-2024-3764** - Low

** DISPUTED ** A vulnerability classified as problematic has been found in Tuya SDK up to 5.0.x. Affected is an unknown function of the component MQTT Packet Handler. The manipulation leads to denial of service. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The real existence of this vulnerability is still doubted at the moment. Upgrading to version 5.1.0 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-260604. NOTE: The vendor explains that a malicious actor would have to crack TLS first or use a legitimate login to initiate the attack.

**التوصية:** Update firmware and implement rate limiting. Monitor for unusual traffic patterns.

---

## التوصيات العامة

1. قم بتحديث البرامج الثابتة لجميع الأجهزة إلى أحدث الإصدارات
2. غيّر كلمات المرور الافتراضية واستخدم كلمات مرور قوية وفريدة
3. فعّل التشفير لجميع الاتصالات (HTTPS, SSL/TLS)
4. أغلق المنافذ والخدمات غير الضرورية
5. راقب حركة الشبكة بانتظام للكشف عن الأنشطة المشبوهة
6. قم بإجراء فحوصات أمنية دورية
7. استخدم شبكة منفصلة لأجهزة IoT (Network Segmentation)
8. فعّل المصادقة الثنائية حيثما أمكن

---

*تم إنشاء هذا التقرير بواسطة أداة فحص أمان أجهزة إنترنت الأشياء*

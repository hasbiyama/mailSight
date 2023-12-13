# mailSight

mailSight is a small utility program I created while delving deeper into email analysis. While it's not intended to be a comprehensive email analysis tool, it serves as a learning project to explore various aspects of email content and structure.

## Features
- **Email Header Parsing**: Parse email headers for .msg, .eml, and .txt formats.
- **Attachment Extraction**: Extract all email attachments (.msg and .eml).
- **Link Analysis**: Identify links, display domains, and download images/documents.
- **DMARC Compliance Check**: Verify DMARC, SPF, and DKIM compliance.
- **Email Address Detection**: Find and list email addresses.
- **QR Code Detection**: Detect and decode QR codes.

## Getting Started

To get started with MailSight, follow these simple steps:

```bash
git clone https://github.com/hasbiyama/mailSight.git
cd mailSight
pip install -r requirements.txt
```
## Usage

```bash
python3 mailSight.py
```
```bash

               .__.__    _________.__       .__     __
  _____ _____  |__|  |  /   _____/|__| ____ |  |___/  |_
 /     \__   \ |  |  |  \_____  \ |  |/ ___\|  |  \   __\
|  Y Y  \/ __ \|  |  |__/        \|  / /_/  >   Y  \  |
|__|_|  (____  /__|____/_______  /|__\___  /|___|  /__|
      \/     \/                \/   /_____/      \/

                <( github.com/hasbiyama )>


>> Usage: mailSight.py <.msg/.eml/.txt path> <outputFolder> [-orgurl]

```

## Results (example)

**Headers**

```bash
<=========================================>

||                                      ||
||               HEADERS                ||
||                                      ||

<=========================================>



 ::::::::::::::::::::::
  Domains
 ::::::::::::::::::::::

[+] aol.com
[+] outlook.com

 ::::::::::::::::::::::
  Senders
 ::::::::::::::::::::::

[+] _______@aol.com

 ::::::::::::::::::::::
  Recipients
 ::::::::::::::::::::::

[+] _______@outlook.com

 ::::::::::::::::::::::
  Return-Path
 ::::::::::::::::::::::

[+] _______@aol.com

 ::::::::::::::::::::::
  Message-ID
 ::::::::::::::::::::::

[+] <807511603.848009.1701865607593@mail.yahoo.com>

 ::::::::::::::::::::::
  IP addresses ( POSSIBLE )
 ::::::::::::::::::::::

[+] 2603:1096:301:f9::5
[+] 2603:10a6:d10:97::8
[+] 2603:10a6:d10:97:cafe::9c
[+] 66.163.185.31

 ::::::::::::::::::::::
  Time
 ::::::::::::::::::::::

[+] Wed, 06 Dec 2023 19:27:13 +0700
[+] Wed, 06 Dec 2023 19:26:56 +0700
[+] Wed, 06 Dec 2023 19:26:54 +0700
[+] Wed, 06 Dec 2023 19:26:53 +0700

 ::::::::::::::::::::::
  (Received from)
 ::::::::::::::::::::::

[+] PUZPR01MB4882.apcprd01.prod.exchangelabs.com
[+] FR0P281CA0127.DEUP281.PROD.OUTLOOK.COM
[+] VI1EUR02FT042.eop-EUR02.prod.protection.outlook.com
[+] sonic313-56.consmr.mail.ne1.yahoo.com

 ::::::::::::::::::::::
  (Received by)
 ::::::::::::::::::::::

[+] SG2PR01MB4147.apcprd01.prod.exchangelabs.com
[+] PUZPR01MB4882.apcprd01.prod.exchangelabs.com
[+] FR0P281CA0127.outlook.office365.com
[+] VI1EUR02FT042.mail.protection.outlook.com

 ::::::::::::::::::::::
  DMARC Compliant
 ::::::::::::::::::::::

[+] DMARC policy is 'reject'
[+] SPF Passed: Sender is authorized and aligned (aol.com)
[+] DKIM alignment is aligned (aol.com).
[-] DKIM signature is invalid.
[-] DKIM validation error: body hash mismatch (got b'47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=', expected b'NoAh9Ny3OoBlVilRJ4nDKJtUro59UBnT8AVauL4RUT4=')

 ::::::::::::::::::::::
  MIME-Version
 ::::::::::::::::::::::

[+]  1.0

 ::::::::::::::::::::::
  Content-Type
 ::::::::::::::::::::::

[+]  multipart/mixed;
        boundary="----=_Part_848008_619866383.1701865607592"
```

**Attachments**

```bash

<=========================================>

||                                      ||
||               ATTACHMENTS            ||
||                                      ||

<=========================================>


[+] frame.png
[+] neuroscience_logo.png
[+] simple_logo_contains_line.png
[+] simple_philosophy_logo.png
[+] x33fcon 2023 - Improving the Stealthiness of Memory Injection Techniques.pdf

```
**Email Body (links)**

```bash

<=========================================>

||                                      ||
||              EMAIL_BODY              ||
||               (links)                ||

<=========================================>



{
    "subject": "Aktivasi aset kripto di Ajaib berhasil",
    "body": [
        "http://mandrillapp.com/contact/abuse?id31098792.e1c4850b88884a87b5321e4a0c320a82X-Mandrill-User:",
        "https://ajaib.co.id",
        "https://ajaib.co.id/",
        "https://www.facebook.com/ajaib.investasi/",
        "https://www.instagram.com/ajaib_investasi/",
        "https://www.youtube.com/channel/UCyQPkTAkLNk_n-NPJebmaIw",
        "https://twitter.com/ajaib_investasi",
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd",
        "http://www.thymeleaf.org",
        "http://www.w3.org/1999/xhtml",
        "https://ajaib-files.s3-ap-southeast-1.amazonaws.com/email_assets/ ... [truncated.]
    ]
}




----------> [ EMAIL_BODY: Domains ]

mandrillapp.com (7)
ajaib.co.id (3)
www.facebook.com (1)
www.instagram.com (1)
www.youtube.com (1)
twitter.com (1)
www.w3.org (2)
www.thymeleaf.org (1)
fonts.googleapis.com (1)

----------> [ EMAIL_BODY: Images ]

[✓] https://ajaib-files.s3-ap-southeast-1.amazonaws.com/email_assets/bg-bottom.jpg
    Download successful!
[✓] https://ajaib-files.s3.ap-southeast-1.amazonaws.com/email_assets/kemendag.png
    Download successful!
[✓] https://d2fi4ri5dhpqd1.cloudfront.net/public/resources/social-networks-icon-sets/circle-color/youtube@2x.png
    Download successful!
[✓] https://ajaib-files.s3.ap-southeast-1.amazonaws.com/email_assets/logo-2022-kti-blue.png
    Download successful!
[✓] https://d2fi4ri5dhpqd1.cloudfront.net/public/resources/social-networks-icon-sets/circle-color/instagram@2x.png
    Download successful!
[✓] https://ajaib-files.s3-ap-southeast-1.amazonaws.com/email_assets/Group-6681.jpg
    Download successful!
[✓] https://d2fi4ri5dhpqd1.cloudfront.net/public/resources/social-networks-icon-sets/circle-color/facebook@2x.png
    Download successful!
[✓] https://d2fi4ri5dhpqd1.cloudfront.net/public/resources/social-networks-icon-sets/circle-color/twitter@2x.png
    Download successful!
[✓] https://ajaib-files.s3.ap-southeast-1.amazonaws.com/email_assets/coin.png
    Download successful!

----------> [ EMAIL_BODY: Documents ]

 ... [truncated.]

```

**QR Codes**

```bash

<=========================================>

||                                      ||
||              QR_CODES                ||
||                                      ||

<=========================================>



[!] QR found!  <[ QR Data ]>

[+] temp/frame.png :: ['https://www.youtube.com/']

```

**Email Addresses**

```bash

<=========================================>

||                                      ||
||           EMAIL_ADDRESSES            ||
||                                      ||

<=========================================>


[+]  _______@repeatexpansionfameghost.net
[+]  _______@7v58h.repeatexpansionfameghost.net
[+]  _______@aol.com
[+]  _______@repeatexpansionfameghost.net

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> [end]

```

## Contributions
Contributions welcome! Open issues or submit pull requests.

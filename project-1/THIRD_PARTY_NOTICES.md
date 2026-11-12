# Third-Party Software & Data Notices

CyberScape incorporates open-source software libraries, packages, and integrates with external threat intelligence and telemetry data sources. Each component is subject to its own respective license and terms of service.

---

## 1. Python Dependencies (from `requirements.txt`)

The following packages are specified in `requirements.txt` and utilized by the Python backend:

| Package | Installed Version | License | Project URL / Source |
| :--- | :--- | :--- | :--- |
| **Flask** | 3.1.3 | BSD-3-Clause | https://palletsprojects.com/p/flask/ |
| **requests** | 2.34.2 | Apache-2.0 | https://requests.readthedocs.io/ |
| **pytest** | 9.2.0 | MIT | https://docs.pytest.org/ |
| **scikit-learn** | 1.9.1 | BSD-3-Clause | https://scikit-learn.org/ |
| **reportlab** | 5.1.0 | BSD License (ReportLab Inc.) | https://www.reportlab.com/ |
| **opencv-python-headless** | 5.0.0.93 | Apache-2.0 | https://github.com/opencv/opencv-python |
| **pyzbar** | 0.1.9 | MIT | https://github.com/NaturalHistoryMuseum/pyzbar |
| **pillow** | 13.0.0 | MIT-CMU | https://python-pillow.org/ |
| **mail-parser** | 4.10.0 | Apache-2.0 | https://github.com/SpamScope/mail-parser |
| **python-dotenv** | 1.2.4 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| **flask-cors** | 6.0.5 | MIT | https://github.com/corydolphin/flask-cors |
| **dnspython** | 2.9.2 | ISC | https://www.dnspython.org/ |

---

## 2. Client-Side Libraries & Vendor Assets

The web interface utilizes the following client-side libraries and stylesheets:

| Library | Distribution | License | Description & Attribution |
| :--- | :--- | :--- | :--- |
| **Lucide Icons** | CDN (`unpkg.com/lucide@latest`) | ISC | Icon library developed by the Lucide community. Copyright (c) Lucide Project. |
| **Tailwind CSS** | CDN (`cdn.tailwindcss.com`) | MIT | Utility-first CSS framework. Copyright (c) Tailwind Labs, Inc. |
| **React 18 & ReactDOM 18** | CDN (`unpkg.com/react@18/umd/`) | MIT | UI rendering framework. Copyright (c) Meta Platforms, Inc. |
| **jsQR** | `static/js/vendor/jsQR.min.js` | Apache-2.0 | Pure JavaScript QR code reading library. Copyright (c) 2017 Cosmotron Co., Ltd. |
| **Leaflet** | `static/js/vendor/leaflet.js` | BSD-2-Clause | Interactive mapping library. Copyright (c) 2010-2023 Vladimir Agafonkin, (c) 2010-2011 CloudMade. |
| **Schibsted Grotesk** | Google Fonts | SIL Open Font License 1.1 | Sans-serif typeface designed by Bakken & Bæck with Schibsted. |
| **JetBrains Mono** | Google Fonts | SIL Open Font License 1.1 | Monospaced typeface created by JetBrains. |

---

## 3. External Threat Intelligence & Telemetry Sources

CyberScape queries external APIs and publicly accessible threat intelligence data feeds to evaluate target domains, IP addresses, URLs, and email headers. Usage of these services is governed by their respective acceptable use policies:

| Provider / Feed | Endpoint / Resource | Terms & Attribution |
| :--- | :--- | :--- |
| **abuse.ch URLhaus** | `https://urlhaus-api.abuse.ch/v1/url/` | Threat intelligence feed providing active malware and phishing campaigns. Offered under Creative Commons CC0 by abuse.ch. |
| **OpenPhish** | `https://openphish.com/feed.txt` | Community phishing feed providing active phishing URL indicators. Governed by OpenPhish Terms of Service. |
| **Google Safe Browsing** | `https://safebrowsing.googleapis.com/v4/` | Threat lists evaluated via API key authentication. Governed by the Google APIs Terms of Service. |
| **VirusTotal** | `https://www.virustotal.com/api/v3/urls/` | Threat scoring API querying multi-engine antivirus consensus. Governed by VirusTotal Terms of Service. |
| **RDAP (Registration Data Access Protocol)** | `https://rdap.org/domain/{domain}` | ICANN standardized directory service providing domain registration age and registrar details according to RFC 7480-7484. |
| **IP-API** | `http://ip-api.com/json/{ip}` | IP geolocation and autonomous system (ASN) telemetry used for academic research and non-commercial evaluation. |

---

## 4. License Excerpts

### BSD-3-Clause License
```text
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.
```

### Apache License 2.0
```text
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

### MIT License
```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

### ISC License
```text
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
```


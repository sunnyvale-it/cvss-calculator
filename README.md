
# NIST NVD Temporal CVSS 3 score calculator

## Purpose

Since the NIST Network Vulnerability Database (NVD) does not support the CVSS 3 Temporal scoring, the script in this repo implements some logic to add this funcionality.

For any CVE, the scripts evaluates all the references recorded into NVD itself and enriches the Base vector string to compute a Temporal score.

## Disclaimer

This script IS NOT production ready and it's just meant to play around with CVSS scoring.

## How to run it

```console
$ pip install -r requirements.txt
```

For example, let's try to calclulate the CVSS 3 Temporal scoring for the CVE-2016-4055 (a.k.a. Spring4Shell)

```console
$ python calc.py CVE-2022-22965             
CVSS 3 base vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS 3 base score: 9.8
CVSS 3 computed final vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RC:C
CVSS 3 computed temporal score: 9.3
CVSS 3 computed overall score: 9.3
```


CheckKarlMarx
=========================================

<img width="1586" alt="report" src="https://user-images.githubusercontent.com/82981657/123410858-734c2180-d5b8-11eb-900d-99cce750b105.png">

Automated tool for security checking mobile app release binaries (apk, ipa). 
CheckKarlMarx good at finding several things:
* network misconfigurations
* insecure, test and basic auth URLs
* various keys, tokens, credentials
* exported components (android)
* insecure webview settings (android)


Usage
-------------

Pull from docker hub and run:

```sh
$ docker pull devkekops/checkkarlmarx
$ docker run -v <path_to_apk_or_ipa>:/mount devkekops/checkkarlmarx /mount
```

It will generate ```report.html``` in ```<path_to_apk_or_ipa>``` folder.

Run with options:

```sh
usage: checkkarlmarx.py [-h] [--html | --sarif] [--file | --stdout] [-o [OUTPUT]] [-d [DOMAINS [DOMAINS ...]]] [-q [QATAGS [QATAGS ...]]] [-p [PACKAGES [PACKAGES ...]]] path

positional arguments:
  path                  path to apk/ipa

optional arguments:
  -h, --help            show this help message and exit
  --html                set report format as html
  --sarif               set report format as sarif
  --file                print report to file
  --stdout              print report to stdout
  -o [OUTPUT], --output [OUTPUT]
                        report filename
  -d [DOMAINS [DOMAINS ...]], --domains [DOMAINS [DOMAINS ...]]
                        domain list (e.g. example.com)
  -q [QATAGS [QATAGS ...]], --qatags [QATAGS [QATAGS ...]]
                        test domain tags list
  -p [PACKAGES [PACKAGES ...]], --packages [PACKAGES [PACKAGES ...]]
                        package names (android only, e.g. com.example)
```

* report format html or sarif (html by default): --html or --sarif
* print report to file or stdout (file by default): --file or --stdout
* report filename (report.html or report.sarif by default): -o --output
* filter found URLs by domain list: -d --domains
* filter test domain URLs by tag list: -q --qatags
* filter found webview settings by package list (android only): -p --packages

Example:
```sh
$ docker run -v $(pwd):/mount devkekops/checkkarlmarx /mount -- sarif --stdout -d mycompany.com -q qa test dev stage -p com.mycompany com.example
```

Exit codes:
* 0 - binary have no vulnerabilities
* 1 - binary have some vulnerabilities
* 2 - something went wrong

For build from sources:
```sh
$ docker build -t my_app .
```

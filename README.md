CheckKarlMarx
=========================================

Automated tool for security checking mobile app release binaries (apk, ipa). 
CheckKarlMarx good at finding several things:
* network misconfigurations
* insecure, test and basic auth URLs
* various keys
* exported components (android)
* insecure webview settings (android)


Usage
-------------

Pull from docker hub and run:

```sh
$ docker pull devkekops/checkkarlmarx
$ docker run -v <path_to_apk_or_ipa>:/mount devkekops/checkkarlmarx
```

It will generate report.html in ```<path_to_apk_or_ipa>``` folder.

Run with options:
* custom report filename: -o --output
* filter found URLs by domain list: -d --domains
* filter test domain URLs by tag list: -q --qatags
* filter found webview settings by package list (android only): -p --packages

Example:
```sh
$ docker run -v ~/myfolder:/mount devkekops/checkkarlmarx -o myreport.html -d mycompany.com -q qa test dev stage -p com.mycompany com.example
```

Exit codes:
* 0 - binary have no vulnerabilities
* 1 - binary have some vulnerabilities
* 2 - something went wrong

For build from sources:
```sh
$ docker build -t my_app .
```
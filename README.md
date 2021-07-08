![Build and deploy to AWS S3](https://github.com/3CORESec/S2AN/workflows/Build%20and%20deploy%20to%20S3/badge.svg)

# S2AN
**S**igma**2A**ttack**N**et - Mapper of Sigma Rules ➡️  MITRE ATT&amp;CK 

S2AN is a standalone tool developed in .NET Core, available for both Linux and Windows (x64), meant to interact with a folder holding [Sigma](https://github.com/Neo23x0/sigma) rules as well as Suricata signatures. Currently the following features are supported:

* Create an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) layer based on the techniques covered by:
**  Sigma rules
** Suricata signatures
* Identify mismatches between tactics and techniques in the Sigma rule files, that could result from improper categorization or updates to the framework

Our main motivation behind its development was to have a tool that we could reference in a CI/CD pipeline when running in a minimal build environment *(without having or wanting to install Python dependencies)*.

Some of S2AN features are based on a [similar tool](https://github.com/Neo23x0/sigma/blob/master/tools/sigma2attack) available in the official Sigma repository.

## Example output

```
$ ./Sigma2AttackNet -d rules/ -w
 
S2AN by 3CORESec - https://github.com/3CORESec/S2AN
 
[*] Layer file written in sigma-coverage.json (6 rules)
 
Attention - mismatch between technique and tactic has been detected!
MITRE ATT&CK technique (T1543.003) and tactic (defense-evasion) mismatch in rule: rules/win_eventlog_service_start_type_mod_error.yml
MITRE ATT&CK technique (T1543.003) and tactic (defense-evasion) mismatch in rule: rules/win_eventlog_service_start_type_mod.yml
MITRE ATT&CK technique (T1003.003) and tactic (credential-dumping) mismatch in rule: rules/win_susp_vssadmin_ntds_activity.yml
```

# Download

You are free to review the source code we make available in this repository. 

The pre-compiled binaries are available for download and you can reference them in your pipeline *(or download for manual execution)* as they will always point towards the latest version:

* GNU/Linux: https://s2an.3coresec.net/linux/Sigma2AttackNet 
* Windows: https://s2an.3coresec.net/windows/Sigma2AttackNet.exe

# Running Sigma2AttackNet

* Generate Navigator layer: `./Sigma2AttackNet -d folder_with_sigma_rules/`
* Generate Navigator layer and identify mismatch: `./Sigma2AttackNet -d folder_with_sigma_rules/ -w`
* Generate Navigator layer from Suricata signatures: `./Sigma2AttackNet -s folder_with_signatures/` 

## Tactic & Technique mismatch

In order to make use of the detection of mismatches in your rules, S2AN expects the following format _(this feature is only available for Sigma rules)_:

```
tags:
  - attack.persistence
  - attack.t1543.003
  - attack.defense_evasion
  - attack.t1562.002
  - attack.t1543.003
``` 

# Example Layer

[Visit this URL](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2F3CORESec%2FS2AN%2Fmaster%2Fexample-layer%2Fsigma-coverage.json) for an example visualization using ATT&CK Navigator of a layer created by S2AN against the public Sigma rules *(as of 02-05-2020)*.

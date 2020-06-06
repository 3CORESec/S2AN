![Build and deploy to AWS S3](https://github.com/3CORESec/S2AN/workflows/Build%20and%20deploy%20to%20S3/badge.svg)

# S2AN
**S**igma**2A**ttack**N**et - Mapper of Sigma Rules ➡️  MITRE ATT&amp;CK 

S2AN is a standalone tool developed in .NET Core, available for both Linux and Windows (x64), that will run through a folder of [Sigma](https://github.com/Neo23x0/sigma) rules and create an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) layer based on the techniques covered by the Sigma rules.

Our main motivation behind its development was to have a tool that we could reference in a CI/CD pipeline when running in a minimal build environment *(without having or wanting to install Python dependencies)*.

S2AN is based on a [similar tool](https://github.com/Neo23x0/sigma/blob/master/tools/sigma2attack) available in the official Sigma repository.

# Download

You are free to review the source code we make available in this repository. 

The pre-compiled binaries are available for download and you can reference them in your pipeline *(or download for manual execution)* as they will always point towards the latest version:

* GNU/Linux: https://s2an.3coresec.net/linux/Sigma2AttackNet 
* Windows: https://s2an.3coresec.net/windows/Sigma2AttackNet.exe

# Running Sigma2AttackNet

`./Sigma2AttackNet -d folder_with_sigma_rules/`

# Considerations

S2AN does not attempt to parse or validate the YAML files. We extract the tags that are relevant for the mapping from the rule file and create our JSON layer solely based on that.

# Example Layer

[Visit this URL](https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2F3CORESec%2FS2AN%2Fmaster%2Fexample-layer%2Fsigma-coverage.json) for an example visualization using ATT&CK Navigator of a layer created by S2AN against the public Sigma rules *(as of 02-05-2020)*.

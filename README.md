![Build and deploy to S3](https://github.com/3CORESec/S2AN/workflows/Build%20and%20deploy%20to%20S3/badge.svg)

# S2AN
**S**igma**2****A**ttack**N**et - Mapper of Sigma Rules ➡️  MITRE ATT&amp;CK 

S2AN is a standalone tool developed in .NET, available for both Linux and Windows, that will run through a folder of [Sigma](https://github.com/Neo23x0/sigma) and create an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) layer based on the techniques covered by the Sigma rules.

Our main motivation behind its development was to have a tool that we could reference in a CI/CD pipeline when running in a minimal build environment *(without having or wanting to install Python dependencies)*.

S2AN is based on a [similar tool](https://github.com/Neo23x0/sigma/blob/master/tools/sigma2attack) available in the official Sigma repository.

# Download

You are free to use the following URLs to include in your pipeline as they will always point towards the lastest version:

* GNU/Linux: https://d12qunpqqrncnn.cloudfront.net/linux/Sigma2AttackNet 
* Windows: https://d12qunpqqrncnn.cloudfront.net/windows/Sigma2AttackNet.exe

# Running Sigma2AttackNet

`./Sigma2AttackNet -d folder_with_sigma_rules/`

# Considerations

S2AN does not attempt to parse or validate the YAML files. We extract the tags that are relevant for the mapping and create our layer JSON solely based on that.

# Example Layer

[Visit this URL]() for an example visualization using ATT&CK Navigator of a layer created by S2AN.

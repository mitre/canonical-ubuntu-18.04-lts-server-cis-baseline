## Baseline Inspec Profile and Hardening for Canonical Ubuntu Version 18.04 Long Term Support (LTS) 

## Description
InSpec compliance profile is a collection of automated tests that validate secure configuration of Canonical Ubuntu Version 18.04 LTS against the CIS Benchmark version 2.0.1.

InSpec is an open-source run-time framework and rule language used to specify compliance,
security, and policy requirements for testing any node in your infrastructure or an infrastructure.

In addition to the InSpec profile, this repository includes content to evaluate accuracy and precision of the validation. Providing the known "Good" and "Bad" datasets elliminates the discussion about
suboptimal level of accuracy.

## Versioning and State of Development
This project uses the [Semantic Versioning Policy](https://semver.org/).

### Branches
The master branch contains the latest version of the software leading up to a new release. Other branches contain feature-specific updates.

### Tags
Tags indicate official releases of the project.
Please note 0.x releases are works in progress (WIP) and may change at any time.

## Requirements
- [ruby](https://www.ruby-lang.org/en/) version 2.6 or greater
- [InSpec](http://inspec.io/) version 4.x or greater
- Install via ruby gem: `gem install inspec`

## Usage
InSpec makes it easy to run tests wherever you need. More options
listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

### Run with remote profile:
You may choose to run the profile via a remote url, this has the
advantage of always being up to date. The disadvantage is you may wish
to modify controls, which is only possible when downloaded. Also, the
remote profile is unintuitive for passing in attributes, which modify
the default values of the profile.

```bash
inspec exec https://github.com/mitre/canonical-ubuntu-18.04-lts-server-cis-baseline/archive/master.tar.gz
```

Another option is to download the profile then run it, this allows
you to edit specific instructions and view the profile code.

```bash
# Clone Inspec Profile
$ git clone --recurse-submodules https://github.com/mitre/canonical-ubuntu-18.04-lts-server-cis-baseline.git

# Run profile locally (assuming you have not changed directories since cloning)
# This will display compliance level at the prompt, and generate a JSON file
# for export called output.json
$ inspec exec canonical-ubuntu-18.04-lts-server-cis-baseline --reporter cli json:output.json

# Run profile with custom settings defined in inspec.yml (previously inputs.yml) against the target
# server example.com.
$ inspec exec canonical-ubuntu-18.04-lts-server-cis-baseline -t example.com --user root --password=Pa55w0rd --reporter cli json:output.json

# Run profile with: custom attributes, ssh keyed into a custom target, and sudo.
$ inspec exec canonical-ubuntu-18.04-lts-server-cis-baseline -t ssh://user@hostname -i /path/to/key --sudo --reporter cli json:output.json

# Run profile with: custom attributes and a Docker container target.
$ inspec exec -t docker://52a949b41213 --input-file=inputs.yml --reporter cli json:output.json
```

If you already cloned the project and forgot `--recurse-submodules`, you can combine the git submodule init and git submodule update steps by running `git submodule update --init --recursive`.


## Running Test-Kitchen

Individually
Create
Vanilla
``` KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create vanilla-ubuntu-1804 ```
Hardened
``` KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create hardened-ubuntu-1804 ```

Converge
Vanilla
``` KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create vanilla-ubuntu-1804 ```
Hardened
``` KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create hardened-ubuntu-1804 ```

Verify
Vanilla
``` KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen verify vanilla-ubuntu-1804 ```
Hardened
``` KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen verify hardened-ubuntu-1804 ```

## Running profile as an end-user

## Review your scan results with [Heimdall-Lite](https://heimdall-lite.mitre.org)
### What is Heimdall-Lite?
Heimdall-Lite is a great open-source Security Results Viewer by the [MITRE Corporation](https://www.mitre.org) for reviewing your GCP CIS Benchmark scan results.
Heimdall-Lite is one of many MITRE [Security Automation Framework](https://saf.mitre.org) (SAF) Supporting Tools working to enhance the Security Automation and DevSecOps communities.
The [MITRE SAF](https://saf.mitre.org) is an open-source community partnership including Government, Industry and the Open Community working together to make truly automated security a reality. It also hosts many InSpec profiles created by the SAF and references to many partner developed profiles - **_including this one_**.
**Tip**: MITRE hosts Heimdall-Lite on GitHub pages, but you can easily run it in your environment via Docker or NPM or whatever suites your need. See the projects GitHub more information.
### Download your JSON formatted results
1. Right click on your `myscan.json` file
2. Then select `Download` to save the `{{project-id}}_scan.json` file locally
### Go to Heimdall Lite and Load your JSON formatted Results
1. Navigate to [Heimdall Lite](https://heimdall-lite.mitre.org)
2. Click `Local Files` on the left side of the loader
3. Drag and Drop or select and load your `{{project-id}}_scan.json` file to review your results.

# Updates
Update submodules
``` git submodule update --init --recursive```

## NOTICE

© 2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE  

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

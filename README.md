# Baseline Inspec Profile and Hardening for Canonical Ubuntu Version 18.04 Long Term Support (LTS) 

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

# canonical-ubuntu-18.04-lts-server-cis-baseline. 

InSpec profile overlay to validate the secure configuration of Canonical Ubuntu 18.04 LTS Server against the [Center for Internet Security](https://www.cisecurity.org/benchmark/ubuntu_linux/) - [CIS Ubuntu Linux 18.04 LTS Benchmark v2.0.1](https://www.cisecurity.org/benchmark/ubuntu_linux/).

## Getting Started  
It is intended and recommended that InSpec and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
__*** Once we have them, put some example inputs here ...***__
```
## Long Running Controls

There are a few long running controls that take anywhere from 3 minutes to 10 minutes or more to run. In an ongoing or CI/CD pipelne this may not be ideal. We have supplied an input (mentioned above in the user-defined inputs) in the profile to allow you to 'skip' these controls to account for these situations.

The input `disable_slow_controls (bool: false)` can be set to `true` or `false` as needed in a `<name_of_your_input_file>.yml` file.

* list

## Running This Overlay Directly from Github

Against a remote target using ssh with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
# How to run 
inspec exec https://github.com/mitre/canonical-ubuntu-18.04-lts-server-cis-baseline/archive/master.tar.gz -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --sudo --sudo-password=<SUDO_PASSWORD_IF_REQUIRED> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
# How to run 
inspec exec https://github.com/mitre/canonical-ubuntu-18.04-lts-server-cis-baseline/archive/master.tar.gz -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a local Ubuntu host with escalated privileges (i.e., InSpec installed on the target)
```bash
# How to run
sudo inspec exec https://github.com/mitre/canonical-ubuntu-18.04-lts-server-cis-baseline/archive/master.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```
### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy
If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.) 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/canonical-ubuntu-18.04-lts-server-cis-baseline.git
inspec archive canonical-ubuntu-18.04-lts-server-cis-baseline
sudo inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd canonical-ubuntu-18.04-lts-server-cis-baseline
git pull
cd ..
inspec archive canonical-ubuntu-18.04-lts-server-cis-baseline --overwrite
sudo inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Review your scan results with [Heimdall-Lite](https://heimdall-lite.mitre.org)
### What is Heimdall-Lite?
Heimdall-Lite is a great open-source Security Results Viewer by the [MITRE Corporation](https://www.mitre.org) for reviewing your GCP CIS Benchmark scan results.  

Heimdall-Lite is one of many MITRE [Security Automation Framework](https://saf.mitre.org) (SAF) Supporting Tools working to enhance the Security Automation and DevSecOps communities.  

The [MITRE SAF](https://saf.mitre.org) is an open-source community partnership including Government, Industry and the Open Community working together to make truly automated security a reality. It also hosts many InSpec profiles created by the SAF and references to many partner developed profiles - **_including this one_**.  

**Tip**: MITRE hosts Heimdall-Lite on GitHub pages, but you can easily run it in your environment via Docker or NPM or whatever suites your need. See the projects GitHub more information.
   
### Go to Heimdall Lite and Load your JSON formatted Results

1. Navigate to [Heimdall Lite](https://heimdall-lite.mitre.org)
2. Click `Local Files` on the left side of the loader
3. Drag and Drop or select and load your `{{project-id}}_scan.json` file to review your results.

## Development, Testing and PRs

```
Describe our testing, and development process here
```
<https://kitchen.ci> has great documeation if you need a reference.
#### Our Pull Request Process
1. Fork the repo
2. Create a branch for your update
3. Update the control or controls
4. If needed, update the hardening content in the `spec` diretory
5. Lint your changes with `inspec check .` at the root of the profile
6. Run the Test Kitchen test suite to ensure your changes will pas CI
7. Submit a PR of your banch aginst the upstream master

#### Test Kitchen Steps

#### Create
This creates a base test target you can use for local testing
- Vanilla & Hardened
``` 
KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create vanilla-ubuntu-1804 

KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create hardened-ubuntu-1804
```

#### Converge
This runs the configuration managment content on the created host
- Vanilla & Hardened
```
KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create vanilla-ubuntu-1804

KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen create hardened-ubuntu-1804
```

#### Verify
This runs the inspec validation profile aginst the host
- Vanilla & Hardened
```
KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen verify vanilla-ubuntu-1804

KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen verify hardened-ubuntu-1804
```

#### Destroy
This will clean up and destroy your testing host

- Vanilla & Hardened
```
KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen verify vanilla-ubuntu-1804

KITCHEN_LOCAL_YAML=kitchen.vagrant.yml CHEF_LICENSE=accept kitchen verify hardened-ubuntu-1804
```

## Update to the repo and sub-modules

Update submodules
```
git submodule update --init --recursive
```

## NOTICE

© 2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE  

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

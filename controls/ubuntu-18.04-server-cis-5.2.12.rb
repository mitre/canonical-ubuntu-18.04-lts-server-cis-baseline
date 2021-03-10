# encoding: UTF-8

control "C-5.2.12" do
  title "Ensure SSH PermitUserEnvironment is disabled"
  desc  "The `PermitUserEnvironment` option allows users to present environment
options to the `ssh` daemon."
  desc  "rationale", "Permitting users the ability to set environment variables
through the SSH daemon could potentially allow users to bypass security
controls (e.g. setting an execution path that has `ssh` executing trojan'd
programs)"
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep permituserenvironment

    PermitUserEnvironment no
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    PermitUserEnvironment no
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_rid: "5.2.12"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('PermitUserEnvironment') { should cmp 'no' }
  end
end

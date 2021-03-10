# encoding: UTF-8

control "C-5.2.11" do
  title "Ensure SSH PermitEmptyPasswords is disabled"
  desc  "The `PermitEmptyPasswords` parameter specifies if the SSH server
allows login to accounts with empty password strings."
  desc  "rationale", "Disallowing remote shell access to accounts that have an
empty password reduces the probability of unauthorized access to the system"
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep permitemptypasswords

    PermitEmptyPasswords no
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    PermitEmptyPasswords no
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["IA-2 (1)"]
  tag cis_level: 1
  tag cis_controls: ["16.3"]
  tag cis_rid: "5.2.11"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end

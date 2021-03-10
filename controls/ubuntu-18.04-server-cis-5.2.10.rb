# encoding: UTF-8

control "C-5.2.10" do
  title "Ensure SSH root login is disabled"
  desc  "The `PermitRootLogin` parameter specifies if the root user can log in
using ssh. The default is no."
  desc  "rationale", "Disallowing root logins over SSH requires system admins
to authenticate using their own individual account, then escalating to root via
`sudo` or `su`. This in turn limits opportunity for non-repudiation and
provides a clear audit trail in the event of a security incident"
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep permitrootlogin

    PermitRootLogin no
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    PermitRootLogin no
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-6 (9)"]
  tag cis_level: 1
  tag cis_controls: ["4.3"]
  tag cis_rid: "5.2.10"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('PermitRootLogin') { should cmp 'no' }
  end
end

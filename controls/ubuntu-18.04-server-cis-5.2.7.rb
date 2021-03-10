# encoding: UTF-8

control "C-5.2.7" do
  title "Ensure SSH MaxAuthTries is set to 4 or less"
  desc  "The `MaxAuthTries` parameter specifies the maximum number of
authentication attempts permitted per connection. When the login failure count
reaches half the number, error messages will be written to the `syslog` file
detailing the login failure."
  desc  "rationale", "Setting the `MaxAuthTries` parameter to a low number will
minimize the risk of successful brute force attacks to the SSH server. While
the recommended setting is 4, set the number based on site policy."
  desc  "check", "
    Run the following command and verify that output `MaxAuthTries` is 4 or
less:

    ```
    # sshd -T | grep maxauthtries

    MaxAuthTries 4
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    MaxAuthTries 4
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-2(12)"]
  tag cis_level: 1
  tag cis_controls: ["16.13"]
  tag cis_rid: "5.2.7"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

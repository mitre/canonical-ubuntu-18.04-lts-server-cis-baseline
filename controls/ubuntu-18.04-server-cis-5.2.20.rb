# encoding: UTF-8

control "C-5.2.20" do
  title "Ensure SSH PAM is enabled"
  desc  "UsePAM Enables the Pluggable Authentication Module interface. If set
to “yes” this will enable PAM authentication using
ChallengeResponseAuthentication and PasswordAuthentication in addition to PAM
account and session module processing for all authentication types"
  desc  "rationale", "When usePAM is set to yes, PAM runs through account and
session types properly. This is important if you want to restrict access to
services based off of IP, time or other factors of the account. Additionally,
you can make sure users inherit certain environment variables on login or
disallow access to the server"
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep -i usepam

    usepam yes
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    UsePAM yes
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-6"]
  tag cis_level: 1
  tag cis_controls: ["5.1"]
  tag cis_rid: "5.2.20"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('UsePAM') { should cmp 'yes' }
  end
end

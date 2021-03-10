# encoding: UTF-8

control "C-5.2.23" do
  title "Ensure SSH MaxSessions is set to 4 or less"
  desc  "The `MaxSessions` parameter specifies the maximum number of open
sessions permitted from a given connection."
  desc  "rationale", "To protect a system from denial of service due to a large
number of concurrent sessions, use the rate limiting function of MaxSessions to
protect availability of sshd logins and prevent overwhelming the daemon."
  desc  "check", "
    Run the following command and verify that output `MaxSessions` is 4 or
less, or matches site policy:

    ```
    # sshd -T | grep -i maxsessions

    maxsessions 4
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    MaxSessions 4
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-6"]
  tag cis_level: 1
  tag cis_controls: ["5.1"]
  tag cis_rid: "5.2.23"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('MaxSessions') { should cmp <= 4 }
  end
end
